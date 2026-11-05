package hosthandler

import (
	"reflect"
	"testing"
)

// TO-DO 216 : la 04_17 d'une purge nomme le nœud à quitter.
func TestLeContenuDeLaPurgeNommeLeNoeud(t *testing.T) {
	obtenu := ContenuActualisation("maintenance du proxy prx01",
		[]string{"192.168.56.10:6668", " ", "172.19.0.5:6666", "a\nb:1"})
	attendu := []string{"maintenance du proxy prx01",
		"quitter 192.168.56.10:6668", "quitter 172.19.0.5:6666"}
	if !reflect.DeepEqual(obtenu, attendu) {
		t.Errorf("contenu = %q", obtenu)
	}
	if got := ContenuActualisation("demande administrateur", nil); len(got) != 1 {
		t.Errorf("sans nœud à quitter : %q", got)
	}
}
