package paquet

import (
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"duckynetworkclient/V1/duckynetwork/storage"
)

// Le jeu de clés appliqué sur la machine — TO-DO 207.

func signerJeuPourTest(t *testing.T, j Jeu, k *rsa.PrivateKey) (string, Enveloppe) {
	t.Helper()
	corps, err := j.Corps()
	if err != nil {
		t.Fatal(err)
	}
	return corps, signerPourTest(t, k, corps)
}

func machineAvec(t *testing.T, cles ...*rsa.PrivateKey) string {
	t.Helper()
	dir := t.TempDir()
	avant := storage.KeyPath
	storage.KeyPath = dir
	t.Cleanup(func() { storage.KeyPath = avant })
	var pubs []*rsa.PublicKey
	for _, k := range cles {
		pubs = append(pubs, &k.PublicKey)
	}
	f, err := FichierCles(Jeu{Numero: 0, Cles: pubs})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, NomFichierCles), []byte(f), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestAppliquerUneRotation(t *testing.T) {
	k1, _ := rsa.GenerateKey(rand.Reader, 3072)
	k2, _ := rsa.GenerateKey(rand.Reader, 3072)
	dir := machineAvec(t, k1)
	if NumeroDuJeu() != 0 {
		t.Fatal("fichier d'installation : numéro 0 attendu")
	}

	// Jeu 1 = {k1, k2}, signé k1 : appliqué.
	c1, e1 := signerJeuPourTest(t, Jeu{Numero: 1, Cles: []*rsa.PublicKey{&k1.PublicKey, &k2.PublicKey}}, k1)
	if j, err := AppliquerJeu(c1, e1); err != nil || j.Numero != 1 {
		t.Fatalf("%+v %v", j, err)
	}
	if cles, _ := ClesDeConfiance(); len(cles) != 2 || NumeroDuJeu() != 1 {
		t.Fatalf("%d clés, n°%d", len(cles), NumeroDuJeu())
	}
	// Rejoué : refusé.
	if _, err := AppliquerJeu(c1, e1); err == nil || !strings.Contains(err.Error(), "rejeu") {
		t.Errorf("rejeu : %v", err)
	}
	// Jeu 2 = {k2}, signé k2 — que la machine tient depuis le jeu 1.
	c2, e2 := signerJeuPourTest(t, Jeu{Numero: 2, Cles: []*rsa.PublicKey{&k2.PublicKey}}, k2)
	if _, err := AppliquerJeu(c2, e2); err != nil {
		t.Fatal(err)
	}
	if cles, _ := ClesDeConfiance(); len(cles) != 1 || NumeroDuJeu() != 2 {
		t.Fatalf("%d clés, n°%d", len(cles), NumeroDuJeu())
	}
	if info, _ := os.Stat(filepath.Join(dir, NomFichierCles)); info.Mode().Perm() != 0o644 {
		t.Errorf("mode %v", info.Mode().Perm())
	}
	if l, _ := filepath.Glob(filepath.Join(dir, "*.vaultaire-jeu")); len(l) != 0 {
		t.Errorf("temporaire laissé : %v", l)
	}
}

// Un jeu signé par une clé que la machine ne tient pas — une compromission
// traitée hors bande, ou une tentative : rien ne change.
func TestUnJeuDUneCleInconnueNeChangeRien(t *testing.T) {
	k1, _ := rsa.GenerateKey(rand.Reader, 3072)
	intrus, _ := rsa.GenerateKey(rand.Reader, 3072)
	dir := machineAvec(t, k1)
	avant, _ := os.ReadFile(filepath.Join(dir, NomFichierCles))
	c, e := signerJeuPourTest(t, Jeu{Numero: 9, Cles: []*rsa.PublicKey{&intrus.PublicKey}}, intrus)
	if _, err := AppliquerJeu(c, e); err == nil || !strings.Contains(err.Error(), "clé inconnue") {
		t.Fatalf("%v", err)
	}
	// Même un jeu qui GARDE k1, s'il est signé par l'intrus.
	c, e = signerJeuPourTest(t, Jeu{Numero: 9, Cles: []*rsa.PublicKey{&k1.PublicKey, &intrus.PublicKey}}, intrus)
	if _, err := AppliquerJeu(c, e); err == nil {
		t.Fatal("jeu de l'intrus accepté")
	}
	// Et un jeu signé k1 mais retouché après coup.
	c, e = signerJeuPourTest(t, Jeu{Numero: 9, Cles: []*rsa.PublicKey{&k1.PublicKey}}, k1)
	if _, err := AppliquerJeu(strings.Replace(c, "\n9\n", "\n8\n", 1), e); err == nil {
		t.Fatal("jeu retouché accepté")
	}
	if apres, _ := os.ReadFile(filepath.Join(dir, NomFichierCles)); string(apres) != string(avant) {
		t.Error("fichier modifié")
	}
}

func TestSansFichierRienNEstApplique(t *testing.T) {
	avant := storage.KeyPath
	storage.KeyPath = t.TempDir()
	t.Cleanup(func() { storage.KeyPath = avant })
	k, _ := rsa.GenerateKey(rand.Reader, 3072)
	c, e := signerJeuPourTest(t, Jeu{Numero: 1, Cles: []*rsa.PublicKey{&k.PublicKey}}, k)
	if _, err := AppliquerJeu(c, e); err == nil {
		t.Fatal("jeu appliqué sur une machine sans clé de confiance")
	}
}

// TO-DO 233 : sans fichier, la machine le dit — et non « 0 », le numéro du
// fichier de l'installation, qui la faisait compter parmi celles qui le tiennent.
func TestSansFichierLeNumeroLeDit(t *testing.T) {
	avant := storage.KeyPath
	storage.KeyPath = t.TempDir()
	t.Cleanup(func() { storage.KeyPath = avant })
	if n := NumeroDuJeu(); n != SansCle {
		t.Fatalf("sans fichier : %d, attendu %d", n, SansCle)
	}
}
