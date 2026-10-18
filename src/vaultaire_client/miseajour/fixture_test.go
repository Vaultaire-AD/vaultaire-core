package miseajour

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"encoding/pem"
	"net/http/httptest"
	"vaultaire_client/paquet"
)

// Le banc des tests du 116 : une installation entière dans un répertoire
// temporaire, un paquet signé par une clé de test, un faux système.

// installationDeTest pose une installation « ancienne » de la famille rocky.
func installationDeTest(t *testing.T) Chemins {
	t.Helper()
	d := t.TempDir()
	c := Chemins{
		Binaire:   filepath.Join(d, "usr/bin/vaultaire_client"),
		Updater:   filepath.Join(d, "usr/libexec/vaultaire/vaultaire_update"),
		Etat:      filepath.Join(d, "var/lib/vaultaire/updates"),
		Unite:     filepath.Join(d, "etc/systemd/system/vaultaire_client.service"),
		OSRelease: filepath.Join(d, "etc/os-release"),
		ReposPAM:  []string{filepath.Join(d, "usr/lib64/security"), filepath.Join(d, "lib/x86_64-linux-gnu/security")},
	}
	ecrire(t, c.OSRelease, "NAME=\"Rocky Linux\"\nID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n", 0o644)
	ecrire(t, c.Binaire, "ancien-vaultaire_client", 0o750)
	ecrire(t, c.Unite, "ancienne-unite", 0o644)
	for _, so := range paquet.Fichiers[1:4] {
		ecrire(t, filepath.Join(c.ReposPAM[0], so), "ancien-"+so, 0o755)
	}
	ecrire(t, filepath.Join(d, "usr/lib64/libnss_vaultaire.so.2"), "ancien-libnss_vaultaire.so.2", 0o755)
	return c
}

func ecrire(t *testing.T, chemin, contenu string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(chemin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(chemin, []byte(contenu), mode); err != nil {
		t.Fatal(err)
	}
}

func lire(t *testing.T, chemin string) string {
	t.Helper()
	b, err := os.ReadFile(chemin)
	if err != nil {
		t.Fatalf("%s : %v", chemin, err)
	}
	return string(b)
}

// destinations : où chaque fichier vit dans l'installation de test.
func destinations(c Chemins) map[string]string {
	pam := c.ReposPAM[0]
	return map[string]string{
		"vaultaire_client":            c.Binaire,
		"pam_login_custom_module.so":  filepath.Join(pam, "pam_login_custom_module.so"),
		"pam_logout_custom_module.so": filepath.Join(pam, "pam_logout_custom_module.so"),
		"pam_ssh_auth_module.so":      filepath.Join(pam, "pam_ssh_auth_module.so"),
		"libnss_vaultaire.so.2":       filepath.Join(filepath.Dir(pam), "libnss_vaultaire.so.2"),
	}
}

// paquetDeTest : l'archive, le manifeste et sa signature d'une version.
type paquetDeTest struct {
	cle       *rsa.PrivateKey
	archive   []byte
	manifeste string
	signature string
	contenus  map[string]string
}

var (
	cleDeTestUne sync.Once
	cleDeTest    *rsa.PrivateKey
)

func cleTest(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	cleDeTestUne.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		cleDeTest = k
	})
	return cleDeTest
}

// fabriquerPaquet : version, famille ; alterer modifie un contenu APRÈS le
// calcul du manifeste (empreinte fausse).
func fabriquerPaquet(t *testing.T, version, famille string, alterer string) paquetDeTest {
	t.Helper()
	p := paquetDeTest{cle: cleTest(t), contenus: map[string]string{}}
	m := paquet.Manifeste{Version: version, Plateforme: paquet.PrefixePlateforme + famille}
	for _, nom := range paquet.Fichiers {
		contenu := "nouveau-" + version + "-" + nom
		somme := sha256.Sum256([]byte(contenu))
		m.Fichiers = append(m.Fichiers, paquet.Fichier{Nom: nom, SHA256: hex.EncodeToString(somme[:])})
		if nom == alterer {
			contenu += "-altere"
		}
		p.contenus[nom] = contenu
	}
	corps, err := m.Corps()
	if err != nil {
		t.Fatal(err)
	}
	p.manifeste = corps
	h := sha256.Sum256([]byte(corps))
	sig, err := rsa.SignPSS(rand.Reader, p.cle, crypto.SHA256, h[:],
		&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	empreinte, _ := paquet.EmpreinteCle(&p.cle.PublicKey)
	p.signature = paquet.Enveloppe{EmpreinteCle: empreinte, Signature: sig}.Texte()

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	ajouter := func(nom, contenu string) {
		_ = tw.WriteHeader(&tar.Header{Name: nom, Mode: 0o755, Size: int64(len(contenu)), Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte(contenu))
	}
	ajouter("vaultaire_client/VERSION", version+"\n")
	ajouter("vaultaire_client/vaultaire_client", p.contenus["vaultaire_client"])
	for _, fam := range []string{"rocky", "debian"} {
		for _, nom := range paquet.Fichiers[1:] {
			c := p.contenus[nom]
			if fam != famille {
				c = "autre-famille-" + nom
			}
			ajouter("vaultaire_client/"+fam+"/"+nom, c)
		}
	}
	_ = tw.Close()
	_ = gz.Close()
	p.archive = buf.Bytes()
	return p
}

// servir rend un Telecharger qui sert le paquet sous base.
func (p paquetDeTest) servir(base, famille, version string) Telecharger {
	fichiers := map[string][]byte{
		URLFichier(base, "", version, NomManifeste(version, famille)): []byte(p.manifeste),
		URLFichier(base, "", version, NomSignature(version, famille)): []byte(p.signature),
		URLFichier(base, "", version, NomArchive(version)):            p.archive,
	}
	return func(url string, max int64) ([]byte, error) {
		if b, ok := fichiers[url]; ok {
			return b, nil
		}
		return nil, fmt.Errorf("%s : HTTP 404", url)
	}
}

// fauxSysteme rejoue les commandes ; reponses[clé] où clé est le nom de la
// commande suivi de ses arguments, ou son seul nom.
type fauxSysteme struct {
	mu       sync.Mutex
	appels   []string
	reponses func(nom string, args []string) ([]byte, error)
}

func (f *fauxSysteme) Systeme(nom string, args ...string) ([]byte, error) {
	f.mu.Lock()
	f.appels = append(f.appels, strings.TrimSpace(filepath.Base(nom)+" "+strings.Join(args, " ")))
	f.mu.Unlock()
	if f.reponses != nil {
		return f.reponses(nom, args)
	}
	return nil, nil
}

func (f *fauxSysteme) aAppele(prefixe string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, a := range f.appels {
		if strings.HasPrefix(a, prefixe) {
			return true
		}
	}
	return false
}

func pemCertificat(srv *httptest.Server) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
}
