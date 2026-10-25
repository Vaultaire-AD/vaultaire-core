package serveurcommunication

import (
	"testing"
	"time"
)

// TO-DO 216 : le nœud courant nommé dans une 04_17 est quitté, après un délai.
func TestLeNoeudCourantNommeEstQuitte(t *testing.T) {
	f, a, p := fermerTunnelMachine, attenteAvantDeQuitter, programmer
	t.Cleanup(func() { fermerTunnelMachine, attenteAvantDeQuitter, programmer = f, a, p })

	fermes := 0
	fermerTunnelMachine = func() { fermes++ }
	attenteAvantDeQuitter = func() time.Duration { return 7 * time.Second }
	var delai time.Duration
	programmer = func(d time.Duration, f func()) { delai = d; f() }

	if !QuitterSiCourant([]string{"192.168.56.10:6668"}, "192.168.56.10:6668") || fermes != 1 || delai != 7*time.Second {
		t.Fatalf("nœud courant nommé : fermé %d fois, délai %s", fermes, delai)
	}
	if QuitterSiCourant([]string{"192.168.56.10:6668"}, "192.168.56.106:6666") || fermes != 1 {
		t.Error("un autre nœud nommé ne doit pas faire quitter le nœud courant")
	}
	if QuitterSiCourant([]string{"192.168.56.10:6668"}, "") || fermes != 1 {
		t.Error("sans tunnel, rien à quitter")
	}
}

func TestLeDelaiResteBorne(t *testing.T) {
	for i := 0; i < 100; i++ {
		if d := attenteAvantDeQuitter(); d < 0 || d >= DelaiMaxQuitter {
			t.Fatalf("délai %s hors de [0, %s[", d, DelaiMaxQuitter)
		}
	}
}
