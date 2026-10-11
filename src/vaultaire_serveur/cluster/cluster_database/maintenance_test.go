package clusterdatabase

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// L'oubli manuel (TO-DO 146) ne retire qu'un nœud HORS LIGNE ET silencieux.
func TestOnNOubliePasUnNoeudVivant(t *testing.T) {
	dernier := time.Now()
	cas := []struct {
		statut     string
		silencieux bool
		refuse     bool
	}{
		{"online", true, true},   // la boucle n'est pas encore passée
		{"offline", false, true}, // hors ligne depuis une seconde : peut revenir
		{"online", false, true},
		{"offline", true, false},
		{"OFFLINE", true, false},
	}
	for _, c := range cas {
		err := refusDOubli(c.statut, c.silencieux, dernier, 3*time.Minute)
		if (err != nil) != c.refuse {
			t.Errorf("%s / silencieux=%v : refus=%v, attendu %v", c.statut, c.silencieux, err != nil, c.refuse)
		}
		if err != nil && !errors.Is(err, ErrNoeudVivant) {
			t.Errorf("le refus n'est pas ErrNoeudVivant : %v", err)
		}
	}
}

// Sentinelle : les DEUX requêtes qui composent les listes servies filtrent la
// maintenance (TO-DO 147). Un nœud en maintenance qui reste dans l'une d'elles
// continue de recevoir du trafic, et la purge le revide sans fin.
func TestLesDeuxListesFiltrentLaMaintenance(t *testing.T) {
	for _, f := range []string{"noeuds_pour_agents.go", "../../ducky-network/host_handler/services_du_cluster.go"} {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(src), "maintenance = FALSE") {
			t.Errorf("%s ne filtre plus la maintenance : un nœud en maintenance y serait servi", f)
		}
	}
}
