package decouverte

import (
	"reflect"
	"testing"
	"time"
)

func reinitEvitement(t *testing.T) {
	t.Helper()
	evitesMu.Lock()
	evites = map[string]time.Time{}
	quitteurs = nil
	evitesMu.Unlock()
	t.Cleanup(func() {
		evitesMu.Lock()
		evites = map[string]time.Time{}
		quitteurs = nil
		maintenant = time.Now
		evitesMu.Unlock()
	})
}

func TestLaTrameDeLaPurgeEstLue(t *testing.T) {
	motif, quitter := LireActualisation("maintenance du proxy prx01\nquitter 192.168.56.10:6668\nquitter [fd00::2]:6666\nautre chose")
	if motif != "maintenance du proxy prx01" || !reflect.DeepEqual(quitter, []string{"192.168.56.10:6668", "[fd00::2]:6666"}) {
		t.Errorf("motif %q, quitter %q", motif, quitter)
	}
	// Une 04_17 d'avant le 216 : le motif seul.
	if motif, quitter := LireActualisation("demande administrateur"); motif != "demande administrateur" || quitter != nil {
		t.Errorf("motif %q, quitter %q", motif, quitter)
	}
}

// TO-DO 216 : le nœud quitté passe en dernier, pour un temps, et reste joignable.
func TestUnNoeudQuittePasseEnDernier(t *testing.T) {
	reinitEvitement(t)
	var recu []string
	SurQuitter(func(a []string) { recu = a })

	adresses := []string{"192.168.56.10:6668", "192.168.56.106:6666", "10.0.0.9:6666"}
	Eviter([]string{"192.168.56.10:6668"})
	if !reflect.DeepEqual(recu, []string{"192.168.56.10:6668"}) {
		t.Errorf("abonné prévenu avec %q", recu)
	}
	if got := enQueue(adresses); !reflect.DeepEqual(got,
		[]string{"192.168.56.106:6666", "10.0.0.9:6666", "192.168.56.10:6668"}) {
		t.Errorf("ordre = %q", got)
	}
	// Seul nœud connu : toujours essayé.
	if got := enQueue([]string{"192.168.56.10:6668"}); len(got) != 1 {
		t.Errorf("le seul nœud a disparu de la liste : %q", got)
	}

	// La fenêtre passée, l'ordre du core revient.
	maintenant = func() time.Time { return time.Now().Add(FenetreEvitement + time.Second) }
	if got := enQueue(adresses); !reflect.DeepEqual(got, adresses) {
		t.Errorf("après la fenêtre : %q", got)
	}
}

func TestMemeAcces(t *testing.T) {
	for _, c := range []struct {
		a, b string
		ok   bool
	}{
		{"192.168.56.10:6668", "192.168.56.10:6668", true},
		{"[fd00::2]:6666", "fd00::2:6666", true},
		{"Proxy.Lan:6666", "proxy.lan:6666", true},
		{"192.168.56.10:6668", "192.168.56.10:6666", false},
		{"", "", false},
	} {
		if MemeAcces(c.a, c.b) != c.ok {
			t.Errorf("MemeAcces(%q, %q) != %v", c.a, c.b, c.ok)
		}
	}
}
