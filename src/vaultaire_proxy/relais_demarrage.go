package main

import (
	"fmt"
	"sync/atomic"
	"time"

	"duckynetworkclient/V1/ducky"
	"duckynetworkclient/V1/duckynetwork/logs"

	"vaultaire_proxy/relais"
)

// PeriodeBilan est l'intervalle du bilan des relais dans le journal.
const PeriodeBilan = 5 * time.Minute

// relaisVivants est le point de rendez-vous entre les relais et le battement du
// nœud — TO-DO 108.
//
// Les deux ne démarrent pas dans le même ordre que celui où ils se lisent : le
// raccordement au cluster lance le battement, PUIS les relais s'ouvrent, parce
// que la liste des cores vers qui relayer vient de la découverte que ce
// raccordement démarre. La goroutine du battement lirait donc une variable
// renseignée après elle par le fil principal — c'est-à-dire une course, et le
// détecteur la signalerait à raison.
//
// Un pointeur atomique plutôt qu'un verrou : l'écriture a lieu une fois, au
// démarrage, et la lecture toutes les vingt secondes. Un mutex n'aurait rien
// protégé de plus, pour une ligne de plus à chaque lecture.
var relaisVivants atomic.Pointer[[]*relais.Serveur]

// demarrerRelais ouvre les ports des relais déjà chargés et lance les
// boucles. Rend une erreur si un relais ne peut pas écouter : c'est à
// l'appelant d'arrêter le proxy.
func demarrerRelais(liste []relais.Relais) ([]*relais.Serveur, error) {
	journal := func(niveau, message string) { logs.Write_log(niveau, message) }

	var serveurs []*relais.Serveur
	for _, r := range liste {
		srv := relais.Nouveau(r, resolveurPour(r), journal)
		if err := srv.Ecouter(); err != nil {
			for _, s := range serveurs {
				_ = s.Fermer()
			}
			return nil, err
		}
		serveurs = append(serveurs, srv)
	}
	for _, srv := range serveurs {
		srv := srv
		logs.Go("relais "+srv.Stats().Nom, func() {
			if err := srv.Servir(); err != nil {
				logs.Write_log("ERROR", fmt.Sprintf("relais arrêté : %v", err))
			}
		})
	}
	// Publiés pour le battement du nœud : c'est lui qui remonte leurs compteurs
	// au core (04_05). Après le démarrage, pour ne jamais publier un relais qui
	// n'écoute pas.
	relaisVivants.Store(&serveurs)

	// Bilan périodique : sans lui, un relais qui refuse tout (aucun core
	// joignable) ne se voit qu'en lisant une ligne par connexion.
	logs.Go("bilan des relais", func() {
		for {
			time.Sleep(PeriodeBilan)
			for _, srv := range serveurs {
				logs.Write_log("INFO", srv.Stats().Resume())
			}
		}
	})
	return serveurs, nil
}

// metriquesRelais compose ce que ce proxy remonte de lui-même à chaque
// battement — TO-DO 108.
//
// # Une seule mesure, et non une par compteur
//
// Six compteurs font six lignes en base toutes les vingt secondes, soit
// vingt-cinq mille par jour et par proxy : la rétention de trente jours en
// garderait près d'un million, pour une vue qui n'en lit jamais qu'une — la
// dernière. La colonne `extra` de `proxy_metrics` est du JSON exactement pour
// cela.
//
// `Valeur` porte les connexions ACTIVES parce que c'est le seul compteur qui ait
// un sens en série temporelle : les autres sont cumulatifs depuis le démarrage,
// et leur courbe ne dirait que « le proxy a redémarré ».
//
// # Le détail par relais est dedans
//
// Un proxy porte plusieurs relais — Ducky, HTTPS, LDAP — et l'agrégat seul ne
// dirait pas lequel refuse. La vue d'ensemble montre la somme ; la fiche d'un
// nœud a de quoi descendre.
func metriquesRelais() []ducky.MetriqueNoeud {
	p := relaisVivants.Load()
	if p == nil || len(*p) == 0 {
		// Avant l'ouverture des relais, ou sur un proxy qui n'en a aucun :
		// rien à dire vaut mieux qu'une ligne de zéros, qui se lirait comme
		// « aucun trafic » là où elle dit « aucun relais ».
		return nil
	}

	var actives, total, refusees, rejetees, montants, descend int64
	detail := make([]map[string]any, 0, len(*p))
	for _, srv := range *p {
		st := srv.Stats()
		actives += st.Actives
		total += st.Total
		refusees += st.Refusees
		rejetees += st.Rejetees
		montants += st.OctetsMontants
		descend += st.OctetsDescend
		detail = append(detail, map[string]any{
			"nom":       st.Nom,
			"type":      string(st.Type),
			"ecoute":    st.Ecoute,
			"actives":   st.Actives,
			"total":     st.Total,
			"refusees":  st.Refusees,
			"rejetees":  st.Rejetees,
			"octets_ms": st.OctetsMontants,
			"octets_ds": st.OctetsDescend,
		})
	}

	return []ducky.MetriqueNoeud{{
		Type:   ducky.TypeMetriqueRelais,
		Valeur: float64(actives),
		Extra: map[string]any{
			"actives":            actives,
			"total":              total,
			"refusees":           refusees,
			"rejetees":           rejetees,
			"octets_montants":    montants,
			"octets_descendants": descend,
			"relais":             detail,
		},
	}}
}
