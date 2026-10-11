package commandsettings

import (
	"strings"
	"testing"

	"vaultaire/core/reglages"
)

// --confirm est retiré où qu'il soit, et n'est jamais pris pour la clé ou la
// valeur (TO-DO 161).
func TestExtraireConfirmation(t *testing.T) {
	cas := []struct {
		args    []string
		reste   string
		confirm bool
	}{
		{[]string{"check_online_minutes", "10"}, "check_online_minutes 10", false},
		{[]string{"check_online_minutes", "10", "--confirm"}, "check_online_minutes 10", true},
		{[]string{"--confirm", "check_online_minutes", "10"}, "check_online_minutes 10", true},
		{[]string{"check_online_minutes", "--CONFIRM", "10"}, "check_online_minutes 10", true},
		{[]string{"check_online_minutes", "--confirme", "10"}, "check_online_minutes --confirme 10", false},
	}
	for _, c := range cas {
		reste, confirm := extraireConfirmation(c.args)
		if strings.Join(reste, " ") != c.reste || confirm != c.confirm {
			t.Errorf("%v -> %v, %v", c.args, reste, confirm)
		}
	}
}

// L'avertissement s'affiche sous la valeur qu'il concerne, et seulement là.
func TestAfficherPorteLAvertissement(t *testing.T) {
	etats := reglages.EtatCourant()
	for i := range etats {
		if etats[i].Cle == reglages.CleVerificationEnLigne {
			etats[i].Avertissement = "à 12 min, 1 machine(s) : pc-b (2.1.4) ne suivent pas"
		}
	}
	sortie := afficher(etats)
	i := strings.Index(sortie, "check_online_minutes")
	j := strings.Index(sortie, "⚠ à 12 min")
	k := strings.Index(sortie, reglages.CleSessionsDucky)
	if i < 0 || j < 0 || !(i < j && j < k) {
		t.Fatalf("avertissement absent ou mal placé :\n%s", sortie)
	}
	if strings.Count(sortie, "⚠") != 1 {
		t.Errorf("avertissement répété :\n%s", sortie)
	}
}
