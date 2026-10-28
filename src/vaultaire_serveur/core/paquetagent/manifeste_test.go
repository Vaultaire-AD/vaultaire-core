package paquetagent

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"strings"
	"sync"
	"testing"
)

// --- le vecteur jumeau ------------------------------------------------------

func TestLeVecteurDeReferenceSeLitEtSeVerifie(t *testing.T) {
	m, err := Lire(corpsReference)
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != "2.3.0" || m.Plateforme != "linux-amd64-rocky" || m.Famille() != "rocky" {
		t.Errorf("manifeste : %+v", m)
	}
	if corps, _ := m.Corps(); corps != corpsReference {
		t.Errorf("Corps ne réécrit pas le vecteur à l'identique :\n%q", corps)
	}
	cles, err := LireClesPubliques([]byte("# commentaire comme dans le fichier déposé\n" + clePubliqueReference))
	if err != nil {
		t.Fatal(err)
	}
	if e, _ := EmpreinteCle(cles[0]); e != empreinteReference {
		t.Errorf("empreinte de la clé : %s, attendu %s", e, empreinteReference)
	}
	env, err := LireEnveloppe(enveloppeReference)
	if err != nil {
		t.Fatal(err)
	}
	if env.Texte() != enveloppeReference {
		t.Error("l'enveloppe ne se réécrit pas à l'identique")
	}
	if _, err := Verifier(corpsReference, env, cles); err != nil {
		t.Errorf("la signature de référence ne se vérifie pas : %v", err)
	}
}

// --- le manifeste -------------------------------------------------------------

func TestLireRefuseToutCeQueCorpsNEcriraitPas(t *testing.T) {
	variantes := map[string]string{
		"sans fin de ligne":    strings.TrimSuffix(corpsReference, "\n"),
		"fin de ligne CRLF":    strings.ReplaceAll(corpsReference, "\n", "\r\n"),
		"ligne vide finale":    corpsReference + "\n",
		"autre domaine":        strings.Replace(corpsReference, "vaultaire-pkg-v1", "vaultaire-gpo-v1", 1),
		"version préversion":   strings.Replace(corpsReference, "2.3.0\n", "2.3.0-rc1\n", 1),
		"version préfixée":     strings.Replace(corpsReference, "2.3.0\n", "v2.3.0\n", 1),
		"plateforme inconnue":  strings.Replace(corpsReference, "linux-amd64-rocky", "windows-amd64", 1),
		"empreinte majuscules": strings.Replace(corpsReference, "0001\n", "000A\n", 1),
		"deux espaces":         strings.Replace(corpsReference, "vaultaire_client ", "vaultaire_client  ", 1),
		"ordre des fichiers":   strings.Replace(strings.Replace(corpsReference, "pam_login_custom_module.so", "X", 1), "pam_logout_custom_module.so", "pam_login_custom_module.so", 1),
		"un fichier de trop":   corpsReference + "extra.so " + strings.Repeat("0", 64) + "\n",
		"un fichier en moins":  strings.Replace(corpsReference, "libnss_vaultaire.so.2 "+strings.Repeat("0", 63)+"5\n", "", 1),
	}
	for nom, corps := range variantes {
		if _, err := Lire(corps); err == nil {
			t.Errorf("%s : accepté", nom)
		}
	}
}

// --- l'archive ------------------------------------------------------------------

type entree struct {
	nom, contenu string
	lien         bool
}

func archive(t *testing.T, entrees ...entree) *bytes.Buffer {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	for _, e := range entrees {
		h := &tar.Header{Name: e.nom, Mode: 0o755, Size: int64(len(e.contenu)), Typeflag: tar.TypeReg}
		if e.lien {
			h = &tar.Header{Name: e.nom, Linkname: "/etc/passwd", Typeflag: tar.TypeSymlink}
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if !e.lien {
			_, _ = tw.Write([]byte(e.contenu))
		}
	}
	_ = tw.Close()
	_ = gz.Close()
	return &b
}

func jeuComplet(familles ...string) []entree {
	es := []entree{
		{nom: "vaultaire_client/VERSION", contenu: "2.3.0\n"},
		{nom: "vaultaire_client/vaultaire_client", contenu: "binaire"},
	}
	for _, f := range familles {
		for _, so := range Fichiers[1:] {
			es = append(es, entree{nom: "vaultaire_client/" + f + "/" + so, contenu: f + so})
		}
	}
	return es
}

func TestDepuisArchiveUnManifesteParFamille(t *testing.T) {
	ms, err := DepuisArchive(archive(t, jeuComplet("rocky", "debian")...))
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 2 || ms[0].Plateforme != "linux-amd64-debian" || ms[1].Plateforme != "linux-amd64-rocky" {
		t.Fatalf("manifestes : %+v", ms)
	}
	binaire := EmpreinteHex(sha256.Sum256([]byte("binaire")))
	for _, m := range ms {
		if m.Version != "2.3.0" || m.Fichiers[0].SHA256 != binaire {
			t.Errorf("%s : %+v", m.Plateforme, m)
		}
		attendu := EmpreinteHex(sha256.Sum256([]byte(m.Famille() + "libnss_vaultaire.so.2")))
		if m.Fichiers[4].SHA256 != attendu {
			t.Errorf("%s : libnss d'une autre famille", m.Plateforme)
		}
	}
}

func TestDepuisArchiveRefuse(t *testing.T) {
	incomplete := jeuComplet("rocky")
	incomplete = incomplete[:len(incomplete)-1] // sans libnss
	sansVersion := jeuComplet("rocky")[1:]
	cas := map[string][]entree{
		"famille incomplète": incomplete,
		"sans VERSION":       sansVersion,
		"sans binaire":       append([]entree{jeuComplet("rocky")[0]}, jeuComplet("rocky")[2:]...),
		"aucune famille":     jeuComplet(),
		"module non classé":  append(jeuComplet("rocky"), entree{nom: "vaultaire_client/pam_ssh_auth_module.so", contenu: "x"}),
		"hors du répertoire": append(jeuComplet("rocky"), entree{nom: "autre/fichier", contenu: "x"}),
		"lien symbolique":    append(jeuComplet("rocky"), entree{nom: "vaultaire_client/lien", lien: true}),
		"remontée de chemin": append(jeuComplet("rocky"), entree{nom: "vaultaire_client/../../etc/x", contenu: "x"}),
		"fichier en double":  append(jeuComplet("rocky"), entree{nom: "vaultaire_client/vaultaire_client", contenu: "autre"}),
		"version illisible":  append([]entree{{nom: "vaultaire_client/VERSION", contenu: "dev"}}, jeuComplet("rocky")[1:]...),
	}
	for nom, es := range cas {
		if _, err := DepuisArchive(archive(t, es...)); err == nil {
			t.Errorf("%s : accepté", nom)
		}
	}
	if _, err := DepuisArchive(strings.NewReader("pas du gzip")); err == nil {
		t.Error("archive illisible acceptée")
	}
}

// --- la signature ---------------------------------------------------------------

var (
	clesDeTest   [2]*rsa.PrivateKey
	clesDeTestMu sync.Once
)

func cleDeTest(t *testing.T, i int) *rsa.PrivateKey {
	t.Helper()
	clesDeTestMu.Do(func() {
		for j := range clesDeTest {
			k, err := rsa.GenerateKey(rand.Reader, 3072)
			if err != nil {
				t.Fatal(err)
			}
			clesDeTest[j] = k
		}
	})
	return clesDeTest[i]
}

func TestSignerPuisVerifier(t *testing.T) {
	k := cleDeTest(t, 0)
	env, err := Signer(corpsReference, k)
	if err != nil {
		t.Fatal(err)
	}
	relue, err := LireEnveloppe(env.Texte())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verifier(corpsReference, relue, []*rsa.PublicKey{&k.PublicKey}); err != nil {
		t.Fatal(err)
	}
	// Un octet changé dans le corps.
	altere := strings.Replace(corpsReference, "0001\n", "0009\n", 1)
	if _, err := Verifier(altere, relue, []*rsa.PublicKey{&k.PublicKey}); err == nil {
		t.Error("corps altéré accepté")
	}
}

// La rotation, prévue dès le format : la machine qui tient l'ancienne ET la
// suivante accepte les deux ; celle qui ne tient que l'ancienne refuse la
// suivante, en la nommant.
func TestDeuxClesDeConfiance(t *testing.T) {
	ancienne, suivante := cleDeTest(t, 0), cleDeTest(t, 1)
	env, err := Signer(corpsReference, suivante)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verifier(corpsReference, env, []*rsa.PublicKey{&ancienne.PublicKey, &suivante.PublicKey}); err != nil {
		t.Errorf("deux clés de confiance : %v", err)
	}
	_, err = Verifier(corpsReference, env, []*rsa.PublicKey{&ancienne.PublicKey})
	if err == nil || !strings.Contains(err.Error(), env.EmpreinteCle) {
		t.Errorf("clé inconnue : %v", err)
	}
}

// L'empreinte de l'enveloppe désigne la clé, elle ne prouve rien : une
// enveloppe qui annonce la bonne empreinte mais porte une signature d'une
// autre clé est refusée.
func TestUneEmpreinteMenteuseNeSuffitPas(t *testing.T) {
	bonne, autre := cleDeTest(t, 0), cleDeTest(t, 1)
	env, _ := Signer(corpsReference, autre)
	env.EmpreinteCle, _ = EmpreinteCle(&bonne.PublicKey)
	if _, err := Verifier(corpsReference, env, []*rsa.PublicKey{&bonne.PublicKey}); err == nil {
		t.Error("signature d'une autre clé acceptée sous la bonne empreinte")
	}
}

func TestSignerRefuse(t *testing.T) {
	petite, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Signer(corpsReference, petite); err == nil {
		t.Error("clé de 2048 bits acceptée")
	}
	if _, err := Signer("n'importe quoi\n", cleDeTest(t, 0)); err == nil {
		t.Error("corps non canonique signé")
	}
}

func TestLireEnveloppeRefuse(t *testing.T) {
	for nom, texte := range map[string]string{
		"vide":           "",
		"autre en-tête":  strings.Replace(enveloppeReference, "vaultaire-pkg-sig-v1", "vaultaire-gpo-v1", 1),
		"sans empreinte": strings.Replace(enveloppeReference, "SHA256:", "MD5:", 1),
		"base64 cassé":   "vaultaire-pkg-sig-v1\n" + empreinteReference + "\n@@@\n",
		"ligne de trop":  enveloppeReference + "x\n",
	} {
		if _, err := LireEnveloppe(texte); err == nil {
			t.Errorf("%s : acceptée", nom)
		}
	}
}

func TestNomManifeste(t *testing.T) {
	m := Manifeste{Plateforme: "linux-amd64-debian"}
	if got := NomManifeste("/r/vaultaire_client-v2.3.0-linux-amd64.tar.gz", m); got !=
		"/r/vaultaire_client-v2.3.0-linux-amd64.tar.gz.debian.manifest" {
		t.Errorf("%s", got)
	}
}
