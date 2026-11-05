package paquetagent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Le vecteur de l'agent est-il CELUI-CI ?
//
// Les deux suites vérifient chacune le vecteur qu'elles portent. Si l'on
// refaisait le vecteur d'un seul côté, chacune resterait verte — et la
// divergence qu'il existe pour attraper passerait. Ce test compare les deux
// fichiers, sous leur ligne « package ».
func TestLeVecteurEstLeMemeQueCeluiDeLAgent(t *testing.T) {
	racine, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(racine, "VERSION")); err == nil {
			break
		}
		parent := filepath.Dir(racine)
		if parent == racine {
			t.Skip("racine du dépôt introuvable : test hors d'une copie du dépôt")
		}
		racine = parent
	}
	lire := func(chemin string) string {
		t.Helper()
		b, err := os.ReadFile(chemin)
		if err != nil {
			t.Fatalf("%v", err)
		}
		_, corps, _ := strings.Cut(string(b), "\n")
		return corps
	}
	ici := lire("vecteur_test.go")
	agent := lire(filepath.Join(racine, "src", "vaultaire_client", "paquet", "vecteur_test.go"))
	if ici != agent {
		t.Error("vecteur_test.go diffère entre le core et l'agent : refaites le vecteur des DEUX côtés")
	}
}
