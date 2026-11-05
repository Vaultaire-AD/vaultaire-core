package logs

import (
	"bytes"
	"strings"
	"testing"
)

// TO-DO 235 : une commande hors ligne envoie son journal ailleurs que sur sa
// sortie ; nil rend la sortie standard.
func TestLeJournalSuitSaDestination(t *testing.T) {
	var b bytes.Buffer
	RedirigerVers(&b)
	defer RedirigerVers(nil)

	Write_Log("INFO", "ldap.limites : bornes en vigueur — essai")
	if !strings.Contains(b.String(), "bornes en vigueur") {
		t.Fatalf("ligne absente de la destination choisie : %q", b.String())
	}

	RedirigerVers(nil)
	if destination() == &b {
		t.Fatal("nil doit rendre la sortie standard")
	}
}
