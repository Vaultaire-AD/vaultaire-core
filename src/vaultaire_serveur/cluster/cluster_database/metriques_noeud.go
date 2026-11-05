package clusterdatabase

import (
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	clusterstorage "vaultaire/cluster/cluster_storage"
	"vaultaire/core/logs"
)

// Lecture des mesures remontées par les nœuds — TO-DO 108.
//
// # Ce que ce fichier NE fait PAS
//
// Il ne trie rien. Le TO-DO affirmait que la liste servie aux agents « tient
// compte » des métriques ; c'était faux — aucune ligne du core ne lisait
// `proxy_metrics`. Le point a été traité en ÉMETTANT les mesures et en les
// MONTRANT, pas en les faisant décider : un nœud qui remonte des chiffres
// flatteurs détournerait sinon le parc vers lui, et les 04_05 sont déclaratives.
//
// Le tri reste donc celui de `noeuds_pour_agents.go` — priorité, affinité de
// groupe, état.

// TypeMetriqueRelais est la chaîne que le proxy range dans `metric_type`.
//
// Écrite des deux côtés, comme les numéros de trame : le core et le SDK ne
// partagent aucun code. Son jumeau est `decouverte.TypeMetriqueRelais`.
const TypeMetriqueRelais = "relais"

// FraicheurMetriques borne l'âge d'une mesure affichable.
//
// Un compteur de connexions ACTIVES est un instantané : passé un certain âge, il
// ne décrit plus rien. L'afficher quand même se lirait comme l'état courant —
// exactement le défaut que ce point corrige, mais dans l'autre sens.
//
// Trois minutes, soit neuf battements manqués à la cadence par défaut du nœud :
// assez pour traverser une coupure brève sans vider la vue, trop peu pour
// montrer les chiffres d'un proxy arrêté.
const FraicheurMetriques = 3 * time.Minute

// TypeMetriqueSessions est le type des mesures qu'un CORE publie de ses
// sessions (TO-DO 148). Écrit et lu par ce seul module : le core est à la fois
// l'auteur et le lecteur.
const TypeMetriqueSessions = "sessions"

// FraicheurPour borne l'âge d'une mesure en tenant compte de la cadence de
// l'émetteur.
//
// Trois minutes conviennent aux proxies et au battement par défaut des cores
// (30 s). Mais `cluster_heartbeat_seconds` se règle : un core qui bat toutes
// les deux minutes publierait une mesure que la vue jugerait périmée un tour
// sur deux, et sa colonne clignoterait. Trois battements, jamais moins que la
// fraîcheur de base.
func FraicheurPour(battement time.Duration) time.Duration {
	if f := 3 * battement; f > FraicheurMetriques {
		return f
	}
	return FraicheurMetriques
}

// ligneMesure est la dernière ligne d'un nœud, avant décodage.
type ligneMesure struct {
	extra string
	quand time.Time
}

// dernieresLignes rend, par nom d'hôte, la plus récente ligne d'un type de
// mesure, dans la fraîcheur donnée. Commune aux relais et aux sessions.
func dernieresLignes(db *sql.DB, typeMesure string, fraicheur time.Duration) map[string]ligneMesure {
	if db == nil {
		return nil
	}
	if fraicheur <= 0 {
		fraicheur = FraicheurMetriques
	}
	rows, err := db.Query(`
		SELECT m.proxy_hostname, COALESCE(m.extra, ''), m.created_at
		  FROM proxy_metrics m
		  JOIN (
		        SELECT proxy_hostname, MAX(id_metric) AS dernier
		          FROM proxy_metrics
		         WHERE metric_type = ? AND created_at >= ?
		      GROUP BY proxy_hostname
		  ) d ON d.dernier = m.id_metric`,
		typeMesure, time.Now().Add(-fraicheur))
	if err != nil {
		logs.Write_Log("WARNING", "cluster: métriques « "+typeMesure+" » illisibles : "+err.Error())
		return nil
	}
	defer func() { _ = rows.Close() }()

	out := map[string]ligneMesure{}
	for rows.Next() {
		var hote string
		var l ligneMesure
		if err := rows.Scan(&hote, &l.extra, &l.quand); err != nil {
			continue
		}
		out[hote] = l
	}
	if err := rows.Err(); err != nil {
		logs.Write_Log("WARNING", "cluster: lecture des métriques interrompue : "+err.Error())
	}
	return out
}

// DernieresMetriquesRelais rend, par nom d'hôte, la dernière mesure de relais.
//
// # Une seule ligne par nœud
//
// La table est une série temporelle : un nœud y a des milliers de lignes. La
// vue n'en veut qu'une, la plus récente. La jointure sur `MAX(id_metric)` la
// prend par l'identifiant et non par la date, parce que deux mesures de la même
// seconde portent la même date — et c'est le cas dès qu'un nœud rattrape un
// retard.
//
// # Une erreur ne remonte pas
//
// Les appelants sont des vues d'état. Refuser d'afficher le cluster parce
// qu'une colonne de supervision est illisible serait un incident là où il n'y a
// qu'un manque. L'erreur est journalisée, la carte rendue vide.
func DernieresMetriquesRelais(db *sql.DB, fraicheur time.Duration) map[string]clusterstorage.MetriquesRelais {
	lignes := dernieresLignes(db, TypeMetriqueRelais, fraicheur)
	if lignes == nil {
		return nil
	}
	out := map[string]clusterstorage.MetriquesRelais{}
	for hote, l := range lignes {
		m, ok := decoderMetriquesRelais(l.extra)
		if !ok {
			continue
		}
		m.Mesure = l.quand
		out[hote] = m
	}
	return out
}

// decoderMetriquesRelais lit la colonne `extra`.
//
// Un JSON illisible est IGNORÉ plutôt que rendu à zéro : la colonne est écrite
// par un nœud, et une ligne de zéros se lirait « ce proxy ne relaie rien »
// quand elle veut dire « ce core ne sait pas lire ce que ce proxy envoie ».
func decoderMetriquesRelais(extra string) (clusterstorage.MetriquesRelais, bool) {
	extra = strings.TrimSpace(extra)
	if extra == "" || extra == "{}" {
		return clusterstorage.MetriquesRelais{}, false
	}
	var m clusterstorage.MetriquesRelais
	if err := json.Unmarshal([]byte(extra), &m); err != nil {
		return clusterstorage.MetriquesRelais{}, false
	}
	return m, true
}

// GarnirMetriquesRelais pose les mesures sur les nœuds d'une liste.
//
// Une fonction plutôt que la même boucle dans chaque vue : la ligne de commande
// et l'interface web affichent la même chose, et deux copies auraient fini par
// diverger sur le cas qui compte — celui du nœud sans mesure.
func GarnirMetriquesRelais(db *sql.DB, noeuds []clusterstorage.Node) {
	if len(noeuds) == 0 {
		return
	}
	mesures := DernieresMetriquesRelais(db, FraicheurMetriques)
	if len(mesures) == 0 {
		return
	}
	for i := range noeuds {
		if m, ok := mesures[noeuds[i].Hostname]; ok {
			m := m
			noeuds[i].Relais = &m
		}
	}
}

// --- les sessions des cores (TO-DO 148) --------------------------------------

// EnregistrerMetriquesSessions écrit la mesure d'un core, à chaque battement.
//
// Dans `proxy_metrics`, malgré son nom : c'est la table des mesures de nœuds,
// déjà purgée par `cluster metrics-retention`, déjà lue par les vues. Une table
// de plus aurait demandé sa propre purge — celle-ci a vécu sans, et en a
// souffert (metriques_purge.go).
//
// metric_value porte le total : la colonne est NOT NULL, et le total est la
// seule valeur qui ait un sens seule.
func EnregistrerMetriquesSessions(db *sql.DB, hostname, ip string, m clusterstorage.MetriquesSessions) error {
	if db == nil {
		return nil
	}
	extra, err := json.Marshal(m)
	if err != nil {
		return err
	}
	_, err = db.Exec(
		`INSERT INTO proxy_metrics (proxy_hostname, proxy_ip, metric_type, metric_value, extra) VALUES (?, ?, ?, ?, ?)`,
		hostname, ip, TypeMetriqueSessions, float64(m.Total()), string(extra))
	return err
}

// decoderMetriquesSessions lit la colonne `extra`. Un JSON illisible est
// ignoré plutôt que rendu à zéro : « ce core ne porte rien » serait faux.
func decoderMetriquesSessions(extra string) (clusterstorage.MetriquesSessions, bool) {
	extra = strings.TrimSpace(extra)
	if extra == "" || extra == "{}" {
		return clusterstorage.MetriquesSessions{}, false
	}
	var m clusterstorage.MetriquesSessions
	if err := json.Unmarshal([]byte(extra), &m); err != nil {
		return clusterstorage.MetriquesSessions{}, false
	}
	return m, true
}

// GarnirMetriquesSessions pose la dernière mesure de sessions sur les nœuds
// d'une liste. Même tolérance que pour les relais : une colonne vide plutôt
// qu'une vue indisponible.
func GarnirMetriquesSessions(db *sql.DB, noeuds []clusterstorage.Node, fraicheur time.Duration) {
	if len(noeuds) == 0 {
		return
	}
	lignes := dernieresLignes(db, TypeMetriqueSessions, fraicheur)
	for i := range noeuds {
		l, ok := lignes[noeuds[i].Hostname]
		if !ok {
			continue
		}
		if m, ok := decoderMetriquesSessions(l.extra); ok {
			m.Mesure = l.quand
			noeuds[i].Sessions = &m
		}
	}
}
