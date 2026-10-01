package decouverte

import (
	"encoding/json"
	"strings"
	"sync"

	"duckynetworkclient/V1/duckynetwork/logs"
)

// Ce qu'un nœud remonte de lui-même, à chaque battement — TO-DO 108.
//
// # Ce qui manquait
//
// La trame 04_05 existait des deux côtés depuis longtemps : le core l'accepte,
// la plafonne à 60 par minute et par nœud, purge sa table au bout de trente
// jours, et expose un réglage de rétention plus deux actions RBAC pour le régler.
// `ConstruireMetrique` était écrite ici. Personne ne l'appelait : la table
// `proxy_metrics` n'avait jamais reçu une ligne, et toute cette mécanique
// tournait à vide.
//
// Une supervision qui affiche une table vide est pire qu'une supervision
// absente : elle se lit comme « aucune charge » alors qu'elle dit « aucune
// mesure ».
//
// # Ce que le point ne fait PAS
//
// Le tri de la liste servie aux agents ne change pas. Le TO-DO affirmait que ce
// tri « en tient compte » — il ne le fait pas, et rien dans le core ne lit
// `proxy_metrics`. Le faire dépendre des mesures serait un autre lot, avec son
// propre risque : un nœud qui remonte des chiffres faux détournerait le parc.
// Ici, les mesures sont VUES, pas obéies.
//
// # Pourquoi le SDK ne connaît pas les relais
//
// Ce paquet est partagé par tous les clients service. Le proxy est le seul à
// avoir des compteurs de relais aujourd'hui ; un service futur en aura d'autres.
// La source est donc branchée par l'appelant, et ce fichier ne sait que
// l'emballer dans une trame.

// TypeMetriqueRelais nomme la mesure que remonte un proxy.
//
// C'est une chaîne de PROTOCOLE, pas un identifiant Go : le core la range telle
// quelle dans `proxy_metrics.metric_type` et la relit pour l'affichage. Elle est
// donc écrite des deux côtés — les deux modules ne partagent aucun code, comme
// pour les numéros de trame.
const TypeMetriqueRelais = "relais"

// Metrique est une mesure qu'un nœud remonte de lui-même.
//
// # Une seule mesure porte tous les compteurs
//
// Un envoi par compteur aurait été plus régulier — six trames, six lignes en
// base. À la cadence du battement, cela fait six lignes toutes les vingt
// secondes et par nœud, soit vingt-cinq mille par jour : la rétention de trente
// jours en garderait presque un million par proxy, pour une vue qui n'en lit
// jamais qu'UNE, la dernière.
//
// La colonne `extra` de `proxy_metrics` est du JSON précisément pour cela. On
// écrit donc une ligne, `Valeur` portant le compteur qu'on veut voir évoluer
// dans le temps, `Extra` le reste.
type Metrique struct {
	// Type est la chaîne rangée dans `metric_type`.
	Type string

	// Valeur est le compteur principal — celui qui a du sens en série
	// temporelle. Pour un proxy : les connexions actives.
	Valeur float64

	// Extra accompagne la valeur. Nil : la trame porte « {} ».
	Extra map[string]any
}

// FournisseurMetriques rend les mesures de l'instant.
//
// Appelé à chaque battement, sur la goroutine du battement : il doit rendre la
// main vite et ne pas bloquer, sinon c'est le battement qui prend du retard —
// et un nœud qui ne bat plus est déclaré hors ligne, donc retiré de la liste
// servie aux agents. Lire des compteurs atomiques est ce qu'on attend ici.
type FournisseurMetriques func() []Metrique

var (
	metriquesMu sync.Mutex
	metriquesFn FournisseurMetriques
)

// ConfigurerMetriques branche la source des mesures. Nil la débranche.
//
// Séparée de DemarrerNoeud parce que l'ordre l'exige : un proxy rejoint le
// cluster AVANT d'ouvrir ses relais — la liste des cores vers qui relayer vient
// de la découverte, que le raccordement démarre. Sa source de compteurs n'existe
// donc pas encore au moment où le battement commence.
func ConfigurerMetriques(f FournisseurMetriques) {
	metriquesMu.Lock()
	metriquesFn = f
	metriquesMu.Unlock()
}

func mesuresCourantes() []Metrique {
	metriquesMu.Lock()
	f := metriquesFn
	metriquesMu.Unlock()
	if f == nil {
		return nil
	}
	return f()
}

// emettreMetriques envoie une 04_05 par mesure rendue par le fournisseur.
//
// Silencieuse quand il n'y a rien à dire : un service sans compteur ne doit pas
// remplir le journal d'une absence qui est son fonctionnement normal.
func emettreMetriques(cle string, n InfosNoeud) {
	if envoyer == nil {
		return
	}
	for _, m := range mesuresCourantes() {
		if strings.TrimSpace(m.Type) == "" {
			// Un type vide se rangerait en base sous une clé que personne ne
			// sait relire. On le dit plutôt que d'écrire une ligne perdue.
			logs.Write_log("WARNING", "nœud : mesure sans type, non remontée")
			continue
		}
		envoyer(ConstruireMetrique(cle, clientID, n, m))
	}
}

// extraJSON encode l'accompagnement d'une mesure.
//
// Rend « {} » plutôt qu'une erreur : le core refuse la trame entière si le JSON
// est invalide, et perdre la mesure parce qu'un champ d'accompagnement ne
// s'encode pas serait la mauvaise moitié à sacrifier.
func extraJSON(extra map[string]any) string {
	if len(extra) == 0 {
		return "{}"
	}
	brut, err := json.Marshal(extra)
	if err != nil {
		logs.Write_log("WARNING", "nœud : accompagnement de mesure inencodable : "+err.Error())
		return "{}"
	}
	return string(brut)
}
