package commandagent

import (
	"strings"
	"testing"

	"vaultaire/core/action"
	dbclients "vaultaire/core/database/db_clients"
	"vaultaire/core/parcversion"
)

func TestAnalyser(t *testing.T) {
	cas := []struct {
		args   []string
		action string
		params action.Params
	}{
		{nil, "agent.status", action.Params{}},
		{[]string{"-g", "pilote"}, "agent.status", action.Params{"group": "pilote"}},
		{[]string{"target", "2.4.0"}, "agent.set_target", action.Params{"version": "2.4.0"}},
		{[]string{"target", "--none"}, "agent.set_target", action.Params{"version": "--none"}},
		{[]string{"target", "-g", "pilote", "2.4.0"}, "agent.set_target",
			action.Params{"group": "pilote", "version": "2.4.0"}},
		{[]string{"pin", "id-c", "none"}, "agent.pin",
			action.Params{"computeur_id": "id-c", "version": "none"}},
	}
	for _, c := range cas {
		d, err := analyser(c.args)
		if err != nil || d.action != c.action || len(d.params) != len(c.params) {
			t.Errorf("%v : %+v, %v", c.args, d, err)
			continue
		}
		for k, v := range c.params {
			if d.params[k] != v {
				t.Errorf("%v : %s=%q, attendu %q", c.args, k, d.params[k], v)
			}
		}
	}
	for _, mauvais := range [][]string{
		{"-g"}, {"target"}, {"target", "-g", "pilote"}, {"target", "1", "2"},
		{"pin", "id-c"}, {"update", "id-c"}, {"n'importe"},
	} {
		if _, err := analyser(mauvais); err == nil {
			t.Errorf("%v accepté", mauvais)
		}
	}
	if d, _ := analyser([]string{"-h"}); !d.aide {
		t.Error("-h ne rend pas l'aide")
	}
}

func TestActionsUtiliseesCouvreLesRoutes(t *testing.T) {
	declarees := map[string]bool{}
	for _, a := range ActionsUtilisees {
		declarees[a] = true
	}
	for _, args := range [][]string{nil, {"target", "1.2.3"}, {"pin", "x", "1.2.3"}} {
		d, _ := analyser(args)
		if !declarees[d.action] {
			t.Errorf("%q absente d'ActionsUtilisees", d.action)
		}
	}
	r := action.NouveauRegistre()
	action.EnregistrerActionsVersionAgent(r)
	for _, nom := range ActionsUtilisees {
		if _, ok := r.Definition(nom); !ok {
			t.Errorf("%q n'est pas enregistrée", nom)
		}
	}
}

func TestRendre(t *testing.T) {
	cible := parcversion.Attendue{Definie: true, Version: parcversion.V(2, 4, 0),
		Source: parcversion.SourceGroupe, Groupe: "pilote"}
	vue := action.VueAgents{
		Parc:             "2.3.0",
		CiblesDesGroupes: []dbclients.CibleGroupe{{Groupe: "pilote", Version: "2.4.0"}},
		Machines: []action.LigneAgent{{ComputeurID: "id-a", Hostname: "pilote-1",
			VersionLisible: "2.3.0", Attendue: cible, Etat: parcversion.EtatEnRetard}},
		Compteurs: map[parcversion.Etat]int{parcversion.EtatEnRetard: 1},
	}
	sortie := rendre(vue)
	for _, morceau := range []string{"Défaut du parc   : 2.3.0", "pilote 2.4.0", "pilote-1",
		"2.4.0 (groupe pilote)", "⚠ en retard", "1 agent(s) : 1 en retard"} {
		if !strings.Contains(sortie, morceau) {
			t.Errorf("sortie sans %q :\n%s", morceau, sortie)
		}
	}

	vide := rendre(action.VueAgents{Machines: []action.LigneAgent{{ComputeurID: "x",
		Etat: parcversion.EtatSansCible}}, Compteurs: map[parcversion.Etat]int{parcversion.EtatSansCible: 1}})
	if !strings.Contains(vide, "Défaut du parc   : aucun") ||
		!strings.Contains(vide, "aucun agent ne sera mis à jour") {
		t.Errorf("parc sans cible :\n%s", vide)
	}
}
