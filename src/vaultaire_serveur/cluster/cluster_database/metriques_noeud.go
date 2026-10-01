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
		TypeMetriqueRelais, time.Now().Add(-fraicheur))
	if err != nil {
		logs.Write_Log("WARNING", "cluster: métriques de relais illisibles : "+err.Error())
		return nil
	}
	defer func() { _ = rows.Close() }()

	out := map[string]clusterstorage.MetriquesRelais{}
	for rows.Next() {
		var hote, extra string
		var quand time.Time
		if err := rows.Scan(&hote, &extra, &quand); err != nil {
			continue
		}
		m, ok := decoderMetriquesRelais(extra)
		if !ok {
			continue
		}
		m.Mesure = quand
		out[hote] = m
	}
	if err := rows.Err(); err != nil {
		logs.Write_Log("WARNING", "cluster: lecture des métriques interrompue : "+err.Error())
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
