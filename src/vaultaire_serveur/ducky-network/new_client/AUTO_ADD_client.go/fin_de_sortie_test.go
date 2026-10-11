package autoaddclientgo

import (
	"strings"
	"testing"
)

// La sortie du script distant est gardée bornée : seule sa fin, celle qui dit
// pourquoi l'installation a échoué, est jointe à l'erreur (TO-DO 153).
func TestFinDeSortieGardeLaFin(t *testing.T) {
	f := &FinDeSortie{Max: 10}
	_, _ = f.Write([]byte("debut-"))
	if f.String() != "debut-" {
		t.Fatalf("sous la borne : %q", f.String())
	}
	n, _ := f.Write([]byte("0123456789ABCDEF"))
	if n != 16 {
		t.Fatalf("Write doit rendre la longueur reçue, pas %d", n)
	}
	if f.String() != "…6789ABCDEF" {
		t.Fatalf("au-delà de la borne : %q", f.String())
	}

	g := &FinDeSortie{Max: TailleFinDeSortie}
	for i := 0; i < 1000; i++ {
		_, _ = g.Write([]byte(strings.Repeat("x", 100) + "\n"))
	}
	_, _ = g.Write([]byte("E: Unable to locate package libpam-vaultaire\n"))
	s := g.String()
	if len(s) > TailleFinDeSortie+len("…") || !strings.HasSuffix(s, "libpam-vaultaire\n") {
		t.Fatalf("100 Ko écrits : %d octets gardés, fin %q", len(s), s[len(s)-30:])
	}
}
