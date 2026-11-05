package paquet

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"duckynetworkclient/V1/duckynetwork/storage"
)

// --- le vecteur jumeau : le même que côté core ---------------------------------

func TestLeVecteurDuCoreSeVerifie(t *testing.T) {
	m, err := Lire(corpsReference)
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != "2.3.0" || m.Famille() != "rocky" || len(m.Fichiers) != 5 {
		t.Errorf("manifeste : %+v", m)
	}
	if corps, _ := m.Corps(); corps != corpsReference {
		t.Errorf("Corps diverge du core :\n%q", corps)
	}
	cles, err := LireClesPubliques([]byte("# commentaire\n" + clePubliqueReference))
	if err != nil {
		t.Fatal(err)
	}
	if e, _ := EmpreinteCle(cles[0]); e != empreinteReference {
		t.Errorf("empreinte : %s, le core écrit %s", e, empreinteReference)
	}
	env, err := LireEnveloppe(enveloppeReference)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verifier(corpsReference, env, cles); err != nil {
		t.Errorf("la signature produite par le core ne se vérifie pas : %v", err)
	}
	if _, err := Verifier(strings.Replace(corpsReference, "2.3.0", "2.3.1", 1), env, cles); err == nil {
		t.Error("une version changée garde sa signature")
	}
}

func TestLireRefuseLeNonCanonique(t *testing.T) {
	for nom, corps := range map[string]string{
		"CRLF":          strings.ReplaceAll(corpsReference, "\n", "\r\n"),
		"domaine GPO":   strings.Replace(corpsReference, "vaultaire-pkg-v1", "vaultaire-gpo-v1", 1),
		"fin manquante": strings.TrimSuffix(corpsReference, "\n"),
		"ligne en plus": corpsReference + "x " + strings.Repeat("0", 64) + "\n",
	} {
		if _, err := Lire(corps); err == nil {
			t.Errorf("%s : accepté", nom)
		}
	}
}

// --- la rotation : deux clés dans le fichier déposé ----------------------------

func signerPourTest(t *testing.T, k *rsa.PrivateKey, corps string) Enveloppe {
	t.Helper()
	h := sha256.Sum256([]byte(corps))
	sig, err := rsa.SignPSS(rand.Reader, k, crypto.SHA256, h[:], optionsPSS)
	if err != nil {
		t.Fatal(err)
	}
	e, _ := EmpreinteCle(&k.PublicKey)
	return Enveloppe{EmpreinteCle: e, Signature: sig}
}

func pemPublique(k *rsa.PrivateKey) string {
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: der}))
}

func TestClesDeConfianceDeuxCles(t *testing.T) {
	ancienne, _ := rsa.GenerateKey(rand.Reader, 3072)
	suivante, _ := rsa.GenerateKey(rand.Reader, 3072)

	dir := t.TempDir()
	avant := storage.KeyPath
	storage.KeyPath = dir
	t.Cleanup(func() { storage.KeyPath = avant })

	if _, err := ClesDeConfiance(); err == nil || !strings.Contains(err.Error(), "aucun paquet") {
		t.Errorf("sans fichier : %v", err)
	}

	contenu := "# Clé publique de signature des paquets\n" + pemPublique(ancienne) +
		"# la suivante, pendant la rotation\n" + pemPublique(suivante)
	if err := os.WriteFile(filepath.Join(dir, NomFichierCles), []byte(contenu), 0o644); err != nil {
		t.Fatal(err)
	}
	cles, err := ClesDeConfiance()
	if err != nil || len(cles) != 2 {
		t.Fatalf("%d clé(s), %v", len(cles), err)
	}
	for _, k := range []*rsa.PrivateKey{ancienne, suivante} {
		if _, err := Verifier(corpsReference, signerPourTest(t, k, corpsReference), cles); err != nil {
			t.Errorf("rotation : %v", err)
		}
	}
	inconnue, _ := rsa.GenerateKey(rand.Reader, 3072)
	if _, err := Verifier(corpsReference, signerPourTest(t, inconnue, corpsReference), cles); err == nil {
		t.Error("clé inconnue acceptée")
	}
}
