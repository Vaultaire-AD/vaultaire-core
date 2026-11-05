package dbrevocation

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vaultaire/core/revocation"
)

// « À rejouer » n'a qu'une définition — TO-DO 49.

func TestLeFiltreSQLDitCommeLeType(t *testing.T) {
	tous := []revocation.TargetStatus{
		revocation.StatusPending, revocation.StatusAcked, revocation.StatusFailed, revocation.StatusLifted,
	}
	for _, s := range tous {
		dansLeFiltre := strings.Contains(sqlARejouer, "'"+string(s)+"'")
		if dansLeFiltre != s.ARejouer() {
			t.Errorf("statut %q : le filtre SQL dit %v, ARejouer dit %v — l'agent et l'interface ne compteraient plus pareil",
				s, dansLeFiltre, s.ARejouer())
		}
	}
	if revocation.StatusLifted.ARejouer() {
		t.Fatal("un verrouillage levé est encore à rejouer : rejoué seul, il referme un compte rétabli")
	}
}

// Aucune requête du paquet ne redéfinit « en attente » à sa façon.
//
// Trois le faisaient (`status <> 'acked'`). Un quatrième statut les aurait fait
// compter le verrouillage levé comme « restant à traiter » pour toujours.
func TestAucuneRequeteNeRedefinitEnAttente(t *testing.T) {
	fichiers, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fichiers {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		contenu, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, ligne := range strings.Split(string(contenu), "\n") {
			nette := strings.TrimSpace(ligne)
			if strings.HasPrefix(nette, "//") {
				continue
			}
			if strings.Contains(nette, "status <>") || strings.Contains(nette, "status !=") {
				// La seule exception : MarkTarget, qui garde une cible LEVÉE
				// d'être ranimée par un compte rendu d'échec.
				if f == "mark_target.go" && strings.Contains(nette, "StatusLifted") {
					continue
				}
				t.Errorf("%s:%d compare le statut par exclusion (%s) — employer sqlARejouer", f, i+1, nette)
			}
		}
	}
}
