package main

import (
	"encoding/json"
	"testing"

	"duckynetworkclient/V1/ducky"

	"vaultaire_proxy/relais"
)

// Ce que ce proxy remonte de lui-même — TO-DO 108.
//
// Le contrat est avec le CORE, qui vit dans un autre dépôt de modules et ne
// partage aucun code avec celui-ci : ce qui compte est donc la forme de ce qui
// part, pas l'appel qui l'a produit.

// Avant l'ouverture des relais, rien n'est remonté.
//
// Ce n'est pas un cas limite : le proxy rejoint le cluster AVANT d'ouvrir ses
// relais — la liste des cores vers qui relayer vient de la découverte que ce
// raccordement démarre. Les premiers battements tombent donc forcément dans
// cette fenêtre, et une ligne de zéros s'y lirait « aucun trafic » alors qu'elle
// dit « aucun relais ».
func TestAvantLOuvertureDesRelaisRienNEstRemonte(t *testing.T) {
	relaisVivants.Store(nil)
	t.Cleanup(func() { relaisVivants.Store(nil) })

	if m := metriquesRelais(); len(m) != 0 {
		t.Errorf("%d mesure(s) remontée(s) sans relais ouvert : %+v", len(m), m)
	}

	vide := []*relais.Serveur{}
	relaisVivants.Store(&vide)
	if m := metriquesRelais(); len(m) != 0 {
		t.Errorf("%d mesure(s) remontée(s) pour une liste vide", len(m))
	}
}

// LE test du point : une seule mesure, et son accompagnement porte le reste.
//
// Une par compteur ferait six lignes en base toutes les vingt secondes et par
// proxy — près d'un million sur la rétention de trente jours, pour une vue qui
// n'en lit jamais qu'une.
func TestLesCompteursTiennentEnUneSeuleMesure(t *testing.T) {
	deux := []*relais.Serveur{
		relais.Nouveau(relais.Relais{Nom: "ducky", Type: relais.TypeDucky, Ecoute: "0.0.0.0:2222"}, nil, nil),
		relais.Nouveau(relais.Relais{Nom: "ldaps", Type: relais.TypeLDAPS, Ecoute: "0.0.0.0:636"}, nil, nil),
	}
	relaisVivants.Store(&deux)
	t.Cleanup(func() { relaisVivants.Store(nil) })

	mesures := metriquesRelais()
	if len(mesures) != 1 {
		t.Fatalf("%d mesure(s), attendu 1", len(mesures))
	}
	m := mesures[0]
	if m.Type != ducky.TypeMetriqueRelais {
		t.Errorf("type %q, attendu %q", m.Type, ducky.TypeMetriqueRelais)
	}

	// Les étiquettes sont celles que le core relit. Le test les nomme une à une
	// plutôt que de comparer une structure : le jour où l'une change, c'est
	// ELLE qu'on veut voir dans le message, pas un diff de carte.
	for _, cle := range []string{"actives", "total", "refusees", "rejetees",
		"octets_montants", "octets_descendants", "relais"} {
		if _, ok := m.Extra[cle]; !ok {
			t.Errorf("étiquette %q absente de l'accompagnement : le core ne la trouvera pas", cle)
		}
	}

	detail, ok := m.Extra["relais"].([]map[string]any)
	if !ok {
		t.Fatalf("le détail par relais n'est pas une liste : %T", m.Extra["relais"])
	}
	if len(detail) != 2 {
		t.Errorf("%d relais dans le détail, attendu 2 — l'agrégat seul ne dirait pas "+
			"lequel des relais refuse", len(detail))
	}
}

// L'accompagnement doit s'encoder en JSON : le core refuse la trame entière
// sinon, et la mesure serait perdue sans que le proxy ne l'apprenne.
func TestLAccompagnementSEncodeEnJSON(t *testing.T) {
	un := []*relais.Serveur{
		relais.Nouveau(relais.Relais{Nom: "ducky", Type: relais.TypeDucky, Ecoute: "0.0.0.0:2222"}, nil, nil),
	}
	relaisVivants.Store(&un)
	t.Cleanup(func() { relaisVivants.Store(nil) })

	brut, err := json.Marshal(metriquesRelais()[0].Extra)
	if err != nil {
		t.Fatalf("accompagnement inencodable : %v", err)
	}

	// Et il se relit tel que le core le lira.
	var relu struct {
		Actives int64 `json:"actives"`
		Relais  []struct {
			Nom    string `json:"nom"`
			Ecoute string `json:"ecoute"`
		} `json:"relais"`
	}
	if err := json.Unmarshal(brut, &relu); err != nil {
		t.Fatalf("accompagnement illisible : %v", err)
	}
	if len(relu.Relais) != 1 || relu.Relais[0].Nom != "ducky" {
		t.Errorf("détail relu = %+v", relu.Relais)
	}
}
