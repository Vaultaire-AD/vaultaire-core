package outil

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vaultaire/core/paquetagent"
)

func ecrireArchive(t *testing.T, dir string) string {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	ajouter := func(nom, contenu string) {
		_ = tw.WriteHeader(&tar.Header{Name: nom, Mode: 0o755, Size: int64(len(contenu)), Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte(contenu))
	}
	ajouter("vaultaire_client/VERSION", "2.3.0\n")
	ajouter("vaultaire_client/vaultaire_client", "binaire")
	for _, f := range []string{"rocky", "debian"} {
		for _, so := range paquetagent.Fichiers[1:] {
			ajouter("vaultaire_client/"+f+"/"+so, f+so)
		}
	}
	_ = tw.Close()
	_ = gz.Close()
	chemin := filepath.Join(dir, "vaultaire_client-v2.3.0-linux-amd64.tar.gz")
	if err := os.WriteFile(chemin, b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return chemin
}

func executer(args []string, ouvrir func() (Cles, error)) (int, string, string) {
	var sortie, erreurs bytes.Buffer
	code := Executer(args, &sortie, &erreurs, ouvrir)
	return code, sortie.String(), erreurs.String()
}

var sansBase = func() (Cles, error) { return Cles{}, errors.New("la base ne doit pas être ouverte") }

func clePEM(t *testing.T) (*rsa.PrivateKey, string, string) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	priv := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}))
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	pub := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: der}))
	return k, priv, pub
}

// La CI : des manifestes non signés, sans configuration ni base.
func TestManifestesNonSignes(t *testing.T) {
	dir := t.TempDir()
	a := ecrireArchive(t, dir)
	code, sortie, erreurs := executer([]string{"--package-manifest", a}, sansBase)
	if code != 0 {
		t.Fatalf("code %d : %s", code, erreurs)
	}
	for _, f := range []string{"rocky", "debian"} {
		corps, err := os.ReadFile(a + "." + f + ".manifest")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := paquetagent.Lire(string(corps)); err != nil {
			t.Errorf("%s : %v", f, err)
		}
		if _, err := os.Stat(a + "." + f + ".manifest.sig"); err == nil {
			t.Errorf("%s : une signature produite sans clé", f)
		}
	}
	if !strings.Contains(sortie, "non signé") {
		t.Errorf("sortie : %s", sortie)
	}
}

func TestSignerHorsLigne(t *testing.T) {
	dir := t.TempDir()
	a := ecrireArchive(t, dir)
	k, priv, _ := clePEM(t)
	fichierCle := filepath.Join(dir, "cle.pem")
	_ = os.WriteFile(fichierCle, []byte(priv), 0o600)

	// Le manifeste de la CI d'abord, puis la signature : c'est le parcours.
	if code, _, e := executer([]string{"--package-manifest", a}, sansBase); code != 0 {
		t.Fatal(e)
	}
	code, sortie, erreurs := executer([]string{"--sign-package", a, "--key", fichierCle}, sansBase)
	if code != 0 {
		t.Fatalf("code %d : %s", code, erreurs)
	}
	for _, f := range []string{"rocky", "debian"} {
		corps, _ := os.ReadFile(a + "." + f + ".manifest")
		sig, _ := os.ReadFile(a + "." + f + ".manifest.sig")
		env, err := paquetagent.LireEnveloppe(string(sig))
		if err != nil {
			t.Fatal(err)
		}
		m, err := paquetagent.Verifier(string(corps), env, []*rsa.PublicKey{&k.PublicKey})
		if err != nil || m.Famille() != f {
			t.Errorf("%s : %v", f, err)
		}
	}
	if !strings.Contains(sortie, "SHA256:") {
		t.Errorf("la sortie ne nomme pas la clé : %s", sortie)
	}
}

// Un manifeste publié qui ne correspond pas à l'archive : rien n'est signé.
func TestManifestePublieDifferent(t *testing.T) {
	dir := t.TempDir()
	a := ecrireArchive(t, dir)
	_, priv, _ := clePEM(t)
	fichierCle := filepath.Join(dir, "cle.pem")
	_ = os.WriteFile(fichierCle, []byte(priv), 0o600)
	_, _, _ = executer([]string{"--package-manifest", a}, sansBase)
	corps, _ := os.ReadFile(a + ".rocky.manifest")
	_ = os.WriteFile(a+".rocky.manifest", []byte(strings.Replace(string(corps), "2.3.0", "2.3.1", 1)), 0o644)

	code, _, erreurs := executer([]string{"--sign-package", a, "--key", fichierCle}, sansBase)
	if code == 0 || !strings.Contains(erreurs, "ne correspond pas") {
		t.Fatalf("code %d : %s", code, erreurs)
	}
	if m, _ := filepath.Glob(a + ".*.sig"); len(m) != 0 {
		t.Errorf("signatures écrites malgré le refus : %v", m)
	}
}

// Avec la base : la relecture se fait avec la clé PUBLIQUE en base. Si elle ne
// va plus avec la privée, rien n'est écrit — le parc refuserait ces paquets.
func TestSignerAvecLaBase(t *testing.T) {
	dir := t.TempDir()
	a := ecrireArchive(t, dir)
	k, _, pub := clePEM(t)
	_, _, autrePub := clePEM(t)

	base := func(publique string) func() (Cles, error) {
		return func() (Cles, error) {
			return Cles{
				Privee:      func() (*rsa.PrivateKey, error) { return k, nil },
				PubliquePEM: func() (string, error) { return publique, nil },
			}, nil
		}
	}
	code, _, erreurs := executer([]string{"--sign-package", a}, base(autrePub))
	if code == 0 || !strings.Contains(erreurs, "ne se vérifie pas") {
		t.Fatalf("clés désaccordées : code %d, %s", code, erreurs)
	}
	if m, _ := filepath.Glob(a + ".*"); len(m) != 0 {
		t.Errorf("fichiers écrits malgré le refus : %v", m)
	}
	if code, _, erreurs := executer([]string{"--sign-package", a}, base(pub)); code != 0 {
		t.Fatalf("code %d : %s", code, erreurs)
	}

	horsLigne := func() (Cles, error) {
		return Cles{Privee: func() (*rsa.PrivateKey, error) { return nil, errors.New("mode hors ligne") }}, nil
	}
	if code, _, erreurs := executer([]string{"--sign-package", a}, horsLigne); code == 0 ||
		!strings.Contains(erreurs, "hors ligne") {
		t.Errorf("hors ligne : code %d, %s", code, erreurs)
	}
}

func TestCle(t *testing.T) {
	dir := t.TempDir()
	k, _, pub := clePEM(t)
	oubliee := false
	ouvrir := func() (Cles, error) {
		return Cles{
			Privee:      func() (*rsa.PrivateKey, error) { return k, nil },
			PubliquePEM: func() (string, error) { return pub, nil },
			Oublier:     func() error { oubliee = true; return nil },
		}, nil
	}

	code, sortie, _ := executer([]string{"--pkg-key", "show"}, ouvrir)
	empreinte, _ := paquetagent.EmpreinteCle(&k.PublicKey)
	if code != 0 || !strings.Contains(sortie, empreinte) || !strings.Contains(sortie, "ce core signe") {
		t.Errorf("show : %d\n%s", code, sortie)
	}

	fichier := filepath.Join(dir, "export.pem")
	if code, _, e := executer([]string{"--pkg-key", "export", fichier}, ouvrir); code != 0 {
		t.Fatal(e)
	}
	info, err := os.Stat(fichier)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("export : %v %v", err, info.Mode())
	}
	relue, _ := os.ReadFile(fichier)
	if rk, err := paquetagent.LireClePrivee(relue); err != nil || !rk.Equal(k) {
		t.Errorf("la clé exportée ne se relit pas : %v", err)
	}
	if code, _, _ := executer([]string{"--pkg-key", "export", fichier}, ouvrir); code == 0 {
		t.Error("un export a écrasé le précédent")
	}

	if code, _, e := executer([]string{"--pkg-key", "forget-private"}, ouvrir); code == 0 || oubliee ||
		!strings.Contains(e, "--confirm") {
		t.Errorf("forget-private sans --confirm : %d %v %s", code, oubliee, e)
	}
	if code, _, _ := executer([]string{"--pkg-key", "forget-private", "--confirm"}, ouvrir); code != 0 || !oubliee {
		t.Error("forget-private --confirm n'a rien fait")
	}
}

func TestSyntaxe(t *testing.T) {
	for _, args := range [][]string{
		{"--package-manifest"},
		{"--sign-package", "a", "--cle", "b"},
		{"--pkg-key"},
		{"--pkg-key", "show", "en-trop"},
		{"--pkg-key", "export"},
		{"--pkg-key", "inconnue"},
	} {
		if code, _, _ := executer(args, sansBase); code == 0 {
			t.Errorf("%v accepté", args)
		}
	}
	if !EstCommande([]string{"--sign-package", "x"}) || EstCommande([]string{"--test"}) {
		t.Error("EstCommande")
	}
}
