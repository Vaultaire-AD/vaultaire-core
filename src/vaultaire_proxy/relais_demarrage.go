package main

import (
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
// Un pointeur atomique plutôt qu'un verrou : l'écriture a lieu au démarrage,
// puis à chaque liste appliquée (TO-DO 141) — quelques fois dans la vie du
// proxy —, et la lecture toutes les vingt secondes. La liste publiée n'est
// jamais modifiée en place : chaque application en pose une nouvelle.
var relaisVivants atomic.Pointer[[]*relais.Serveur]

// lancerLeBilan écrit périodiquement l'état des relais dans le journal.
//
// Sans lui, un relais qui refuse tout (aucun core joignable) ne se voit qu'en
// lisant une ligne par connexion. La liste est relue à chaque tour : les relais
// changent maintenant pendant que le proxy tourne (TO-DO 141).
func lancerLeBilan() {
	logs.Go("bilan des relais", func() {
		for {
			time.Sleep(PeriodeBilan)
			if p := relaisVivants.Load(); p != nil {
				for _, srv := range *p {
					logs.Write_log("INFO", srv.Stats().Resume())
				}
			}
		}
	})
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
