package keymanagement

import (
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vaultaire/core/paquetagent"
)

// Une machine installée reçoit le DERNIER jeu publié, numéro compris
// (TO-DO 207) — pas la seule clé active.
func TestLInstallationDeposeLeDernierJeu(t *testing.T) {
	a, _ := rsa.GenerateKey(rand.Reader, 3072)
	b, _ := rsa.GenerateKey(rand.Reader, 3072)
	avant := jeuDeLInstallation
	t.Cleanup(func() { jeuDeLInstallation = avant })
	jeuDeLInstallation = func() (paquetagent.Jeu, error) {
		return paquetagent.Jeu{Numero: 4, Cles: []*rsa.PublicKey{&a.PublicKey, &b.PublicKey}}, nil
	}
	dir := t.TempDir()
	if err := EcrireClePaquetsPourClient(dir); err != nil {
		t.Fatal(err)
	}
	contenu, _ := os.ReadFile(filepath.Join(dir, PkgPublicKeyFileName))
	if paquetagent.NumeroDuFichier(string(contenu)) != 4 || strings.Count(string(contenu), "BEGIN RSA PUBLIC KEY") != 2 {
		t.Fatalf("%s", contenu)
	}
	if cles, err := paquetagent.LireClesPubliques(contenu); err != nil || len(cles) != 2 {
		t.Fatalf("%v", err)
	}
	info, _ := os.Stat(filepath.Join(dir, PkgPublicKeyFileName))
	if info.Mode().Perm() != 0o644 {
		t.Errorf("mode %v", info.Mode().Perm())
	}
	// Sans jeu publié : numéro 0, pas de ligne de numéro.
	jeuDeLInstallation = func() (paquetagent.Jeu, error) {
		return paquetagent.Jeu{Cles: []*rsa.PublicKey{&a.PublicKey}}, nil
	}
	_ = EcrireClePaquetsPourClient(dir)
	contenu, _ = os.ReadFile(filepath.Join(dir, PkgPublicKeyFileName))
	if strings.Contains(string(contenu), paquetagent.MarqueNumeroJeu) {
		t.Errorf("numéro 0 écrit :\n%s", contenu)
	}
}

func TestLesRolesOntLeursNoms(t *testing.T) {
	for role, nom := range map[string]string{paquetagent.RoleActive: "pkg_signing",
		paquetagent.RoleSuivante: "pkg_signing_next", paquetagent.RolePrecedente: "pkg_signing_previous"} {
		if n, err := nomDuRole(role); err != nil || n != nom {
			t.Errorf("%s : %q %v", role, n, err)
		}
	}
	if _, err := nomDuRole("autre"); err == nil {
		t.Error("rôle inconnu accepté")
	}
}
