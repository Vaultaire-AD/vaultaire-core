package parcversion

import (
	"strings"
	"testing"
)

// Ce que ces tests gardent : une version illisible n'est JAMAIS rangée « à
// jour », et la métadonnée de build n'entre dans aucune comparaison.

func TestLireLesFormesDeclarees(t *testing.T) {
	for declaree, attendue := range map[string]string{
		"2.3.0+g1939a3b (2026-08-14)": "2.3.0",
		"2.2.0 (build local)":         "2.2.0",
		"2.1.12":                      "2.1.12",
		"v2.2.1":                      "2.2.1",
		"  2.2.0  ":                   "2.2.0",
		"2.4.0-rc1":                   "2.4.0",
		"10.0.0+gabc":                 "10.0.0",
	} {
		v, ok := Lire(declaree)
		if !ok || v.String() != attendue {
			t.Errorf("Lire(%q) = %v, %v ; attendu %s", declaree, v, ok, attendue)
		}
	}
}

func TestUneVersionIllisibleNEstPasLue(t *testing.T) {
	for _, declaree := range []string{
		"", "dev", "inconnue", "2.2", "2", "2.2.x", "2..0", "2.2.0.1", "-1.2.0",
		"+g1939a3b", "(build local)", "2.2.99999999",
	} {
		if v, ok := Lire(declaree); ok {
			t.Errorf("Lire(%q) = %v : une version illisible a été lue", declaree, v)
		}
	}
}

func TestAvant(t *testing.T) {
	cas := []struct {
		a, b  Version
		avant bool
	}{
		{V(2, 1, 9), V(2, 2, 0), true},
		{V(2, 2, 0), V(2, 2, 0), false},
		{V(2, 2, 1), V(2, 2, 0), false},
		{V(1, 9, 9), V(2, 0, 0), true},
		{V(2, 10, 0), V(2, 2, 0), false}, // numérique, pas lexicographique
		{V(3, 0, 0), V(2, 9, 9), false},
	}
	for _, c := range cas {
		if got := c.a.Avant(c.b); got != c.avant {
			t.Errorf("%v.Avant(%v) = %v", c.a, c.b, got)
		}
	}
}

func TestRecenser(t *testing.T) {
	parc := []Machine{
		{ComputeurID: "id-z", Hostname: "zeta", Declaree: "2.1.0+gaaa (2026-08-01)"},
		{ComputeurID: "id-a", Hostname: "alpha", Declaree: "2.3.0+gbbb (2026-10-07)"},
		{ComputeurID: "id-b", Hostname: "beta", Declaree: ""},
		{ComputeurID: "id-c", Hostname: "", Declaree: "dev"},
		{ComputeurID: "id-d", Hostname: "delta", Declaree: "2.2.0"},
		{ComputeurID: "id-e", Hostname: "epsilon", Declaree: "2.0.3"},
	}
	b := Recenser(parc, V(2, 2, 0))
	if b.Total != 6 || len(b.Anterieures) != 2 || len(b.Inconnues) != 2 || b.ARisque() != 4 {
		t.Fatalf("bilan = %+v", b)
	}
	// Triées par nom, antérieures d'abord ; une machine sans nom montre son id.
	got := strings.Join(b.Premieres(10), " | ")
	want := "epsilon (2.0.3) | zeta (2.1.0) | beta (jamais déclarée) | id-c (illisible : dev)"
	if got != want {
		t.Errorf("Premieres =\n  %s\nattendu\n  %s", got, want)
	}
	if r := b.Resume(2); r != "4 machine(s) : epsilon (2.0.3), zeta (2.1.0) et 2 autre(s)" {
		t.Errorf("Resume(2) = %q", r)
	}
	if r := b.Resume(5); strings.Contains(r, "autre") {
		t.Errorf("Resume(5) annonce un reste qui n'existe pas : %q", r)
	}
}

func TestUnParcAJourNARienARisque(t *testing.T) {
	b := Recenser([]Machine{{Hostname: "a", Declaree: "2.2.0"}, {Hostname: "b", Declaree: "2.3.1+g1"}}, V(2, 2, 0))
	if b.ARisque() != 0 {
		t.Fatalf("parc à jour compté à risque : %+v", b)
	}
	if b := Recenser(nil, V(2, 2, 0)); b.ARisque() != 0 || b.Total != 0 {
		t.Fatalf("parc vide : %+v", b)
	}
}
