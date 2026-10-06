package commandcluster

import (
	"strings"
	"testing"

	"vaultaire/core/action"
)

// Les options de « cluster relais <proxy> set » (TO-DO 141).
//
// Une option absente doit rester ABSENTE des paramètres : sur un relais qui
// existe, c'est ce qui dit à l'action « n'y touche pas ».
func TestLesOptionsDeRelais(t *testing.T) {
	p := action.Params{"node": "proxy1", "name": "nexus"}
	motif := lireOptionsDeRelais([]string{"--type", "https", "--ecoute=:8843", "--source", "service:vaultaire_nexus", "--max", "200"}, p)
	if motif != "" {
		t.Fatalf("options valides refusées : %s", motif)
	}
	for nom, attendu := range map[string]string{"type": "https", "listen": ":8843", "source": "service:vaultaire_nexus", "max_connections": "200"} {
		if p[nom] != attendu {
			t.Errorf("paramètre %s = %q, attendu %q", nom, p[nom], attendu)
		}
	}
	for _, absent := range []string{"addresses", "target_port", "idle", "connect_timeout", "max_per_source"} {
		if p.Presente(absent) {
			t.Errorf("paramètre %s posé alors que l'option n'a pas été donnée : il effacerait le réglage du relais", absent)
		}
	}

	for nom, args := range map[string][]string{
		"option inconnue":      {"--port", "443"},
		"valeur manquante":     {"--type"},
		"option donnée 2 fois": {"--max", "1", "--max=2"},
		"alias donné 2 fois":   {"--ecoute", ":1", "--listen", ":2"},
	} {
		if motif := lireOptionsDeRelais(args, action.Params{}); motif == "" {
			t.Errorf("%s : acceptée", nom)
		}
	}
}

// La commande sans droit ni base ne doit pas paniquer, et l'aide doit dire
// l'essentiel : les trois sous-commandes et la clé à demander.
func TestLAideDesRelais(t *testing.T) {
	aide := relais(nil, action.Appelant{})
	for _, attendu := range []string{"set <nom>", "remove <nom>", "release", "write:relay", "pilotage", "SANS REDÉMARRER"} {
		if !strings.Contains(strings.ReplaceAll(aide, "PREND LA MAIN", "pilotage"), attendu) {
			t.Errorf("aide sans %q", attendu)
		}
	}
	if !strings.Contains(relais([]string{"proxy1", "explose"}, action.Appelant{}), "inconnue") {
		t.Error("sous-commande inconnue non signalée")
	}
	if !strings.Contains(relais([]string{"proxy1", "set"}, action.Appelant{}), "nom du relais manquant") {
		t.Error("« set » sans nom non signalé")
	}
}
