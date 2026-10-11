package clusterdatabase

import (
	"encoding/json"
	"testing"
	"time"

	clusterstorage "vaultaire/cluster/cluster_storage"
)

// Les sessions publiées par un core (TO-DO 148) : ce qui est écrit se relit.
func TestLesSessionsPublieesSeRelisent(t *testing.T) {
	ecrit, err := json.Marshal(clusterstorage.MetriquesSessions{Machines: 42, Tunnels: 45, Comptes: 3, Poignees: 1})
	if err != nil {
		t.Fatal(err)
	}
	m, ok := decoderMetriquesSessions(string(ecrit))
	if !ok || m.Machines != 42 || m.Tunnels != 45 || m.Comptes != 3 || m.Poignees != 1 {
		t.Fatalf("relu %+v depuis %s", m, ecrit)
	}
	if m.Total() != 49 {
		t.Errorf("Total = %d", m.Total())
	}
}

// Illisible n'est pas zéro : « ce core ne porte rien » serait une affirmation
// fausse, et la plus trompeuse possible avant une purge (TO-DO 147).
func TestDesSessionsIllisiblesNeSeLisentPasZero(t *testing.T) {
	for _, extra := range []string{"", "{}", "pas du json", "[1,2]"} {
		if m, ok := decoderMetriquesSessions(extra); ok {
			t.Errorf("%q relu comme %+v", extra, m)
		}
	}
}

func TestLaFraicheurSuitLeBattement(t *testing.T) {
	if f := FraicheurPour(30 * time.Second); f != FraicheurMetriques {
		t.Errorf("battement par défaut : %v", f)
	}
	if f := FraicheurPour(2 * time.Minute); f != 6*time.Minute {
		t.Errorf("battement de 2 min : %v — la mesure serait jugée périmée un tour sur deux", f)
	}
}

func TestSessionsLisibles(t *testing.T) {
	cas := map[clusterstorage.MetriquesSessions]string{
		{Machines: 42, Comptes: 3}:              "42 m · 3 c",
		{Machines: 42, Comptes: 3, Poignees: 2}: "42 m · 3 c · 2 p",
		{}:                                      "0 m · 0 c",
	}
	for m, attendu := range cas {
		if got := m.Lisible(); got != attendu {
			t.Errorf("%+v -> %q, attendu %q", m, got, attendu)
		}
	}
}
