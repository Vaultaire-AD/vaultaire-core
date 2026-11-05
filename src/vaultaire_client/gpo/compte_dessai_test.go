package gpo

import (
	"os/user"
	"testing"
)

// Sans contrainte de système : drift_user_test.go s'en sert aussi, et il n'est
// pas réservé à Linux.

// compteDEssai rend un compte local réel et un dossier personnel à lui.
//
// Le compte est celui qui lance les tests : l'écriture sûre vérifie que chaque
// répertoire appartient à l'uid cible, et le dossier temporaire du test
// appartient à celui qui le crée. `resolveHomeDir` est détourné vers ce
// dossier — le vrai `HOME` de qui lance les tests n'est jamais touché.
func compteDEssai(t *testing.T) (nom, home string) {
	t.Helper()
	moi, err := user.Current()
	if err != nil {
		t.Skipf("compte courant illisible : %v", err)
	}
	home = t.TempDir()

	ancien := resolveHomeDir
	resolveHomeDir = func(string) (string, error) { return home, nil }
	t.Cleanup(func() { resolveHomeDir = ancien })
	return moi.Username, home
}
