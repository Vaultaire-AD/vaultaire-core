package serveurauth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"duckynetworkclient/V1/duckynetwork/storage"
)

// Le scénario que ces tests reproduisent est celui du point 14 de l'audit :
// un tiers répond à la place du core au moment où l'agent demande sa clé.
//
// Ce moment est unique dans la vie de la machine — la clé écrite n'est plus
// jamais redemandée — et il se produisait sans qu'aucune trace n'en subsiste.

func clePubliquePEM(t *testing.T) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("génération de clé : %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("encodage DER : %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// repertoireDeTest isole KeyPath. Sans cela, les tests liraient et écriraient
// dans /etc/vaultaire_client/.ssh de la machine qui les exécute.
func repertoireDeTest(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	ancien := storage.KeyPath
	storage.KeyPath = dir
	t.Cleanup(func() { storage.KeyPath = ancien })
	return dir
}

// TestCleSubstitueeEstRefusee est le test qui compte.
//
// Une empreinte est en place ; une AUTRE clé se présente. C'est exactement la
// substitution que le point 14 décrivait, et elle passait auparavant sans
// aucun signe.
func TestCleSubstitueeEstRefusee(t *testing.T) {
	repertoireDeTest(t)

	cleDuCore := clePubliquePEM(t)
	cleDeLAttaquant := clePubliquePEM(t)

	empreinteLegitime, err := EmpreinteClePublique(cleDuCore)
	if err != nil {
		t.Fatalf("empreinte : %v", err)
	}
	if err := EcrireEmpreinte(empreinteLegitime); err != nil {
		t.Fatalf("écriture de l'empreinte : %v", err)
	}

	_, err = VerifierCleCore(cleDeLAttaquant)
	if err == nil {
		t.Fatal("la clé d'un tiers est acceptée alors qu'une empreinte est en place")
	}

	var e *ErrCleCoreInattendue
	if !errors.As(err, &e) {
		t.Fatalf("erreur de type %T, attendu *ErrCleCoreInattendue — "+
			"l'appelant ne peut pas distinguer ce cas d'une panne réseau", err)
	}

	// Le message doit permettre d'agir. Un refus sans indication de quoi faire
	// pousse à effacer les fichiers au hasard — c'est-à-dire à accepter
	// l'imposteur pour faire cesser l'erreur.
	msg := e.Error()
	for _, attendu := range []string{empreinteLegitime, "vlt certificate show core", CoreFingerprintPath()} {
		if !strings.Contains(msg, attendu) {
			t.Errorf("le message de refus ne contient pas %q", attendu)
		}
	}
}

// TestCleLegitimeEstAcceptee : la vérification ne doit pas refuser la bonne clé.
//
// Un test qui ne contrôlerait que les refus passerait sur un code qui refuse
// TOUT — lequel serait parfaitement sûr et parfaitement inutilisable.
func TestCleLegitimeEstAcceptee(t *testing.T) {
	repertoireDeTest(t)

	cleDuCore := clePubliquePEM(t)
	empreinte, err := EmpreinteClePublique(cleDuCore)
	if err != nil {
		t.Fatalf("empreinte : %v", err)
	}
	if err := EcrireEmpreinte(empreinte); err != nil {
		t.Fatalf("écriture : %v", err)
	}

	avertissement, err := VerifierCleCore(cleDuCore)
	if err != nil {
		t.Fatalf("la clé légitime est refusée : %v", err)
	}
	if avertissement != "" {
		t.Fatalf("avertissement inattendu alors que l'empreinte correspond : %s", avertissement)
	}
}

// TestSansEmpreinteAccepteMaisAvertit.
//
// Une machine installée à la main n'a pas d'empreinte. Refuser de démarrer
// rendrait l'installation manuelle impossible ; accepter en silence ramènerait
// au défaut d'origine. D'où l'avertissement, qui laisse une trace.
func TestSansEmpreinteAccepteMaisAvertit(t *testing.T) {
	repertoireDeTest(t)

	cleQuelconque := clePubliquePEM(t)

	avertissement, err := VerifierCleCore(cleQuelconque)
	if err != nil {
		t.Fatalf("refus alors qu'aucune empreinte n'est en place : %v", err)
	}
	if avertissement == "" {
		t.Fatal("acceptation SILENCIEUSE sans empreinte : rien ne distinguerait " +
			"une machine attestée d'une machine qui ne l'est pas")
	}
	empreinte, _ := EmpreinteClePublique(cleQuelconque)
	if !strings.Contains(avertissement, empreinte) {
		t.Error("l'avertissement ne mentionne pas l'empreinte acceptée — " +
			"impossible de la comparer après coup à celle du core")
	}
}

// TestEmpreinteInsensibleALaMiseEnForme.
//
// Le PEM est une enveloppe texte. Saut de ligne final, terminaisons CRLF d'un
// fichier passé par Windows : la clé est identique, la mise en forme non.
//
// Une empreinte qui varierait avec ces détails produirait un refus disant
// « la clé du core a changé » sur une clé qui n'a pas bougé — le pire des
// diagnostics, puisqu'il oriente vers la mauvaise conclusion.
func TestEmpreinteInsensibleALaMiseEnForme(t *testing.T) {
	base := clePubliquePEM(t)

	variantes := map[string]string{
		"telle quelle":      base,
		"sans saut final":   strings.TrimRight(base, "\n"),
		"CRLF":              strings.ReplaceAll(base, "\n", "\r\n"),
		"espaces autour":    "  \n" + base + "  \n",
		"double saut final": base + "\n",
	}

	reference, err := EmpreinteClePublique(base)
	if err != nil {
		t.Fatalf("empreinte : %v", err)
	}

	for nom, variante := range variantes {
		t.Run(nom, func(t *testing.T) {
			got, err := EmpreinteClePublique(variante)
			if err != nil {
				t.Fatalf("variante refusée : %v", err)
			}
			if got != reference {
				t.Fatalf("empreinte différente pour la même clé : %s vs %s", got, reference)
			}
		})
	}
}

// TestFormeDeLEmpreinte : « SHA256:<base64> », comme ssh-keygen -lf.
func TestFormeDeLEmpreinte(t *testing.T) {
	empreinte, err := EmpreinteClePublique(clePubliquePEM(t))
	if err != nil {
		t.Fatalf("empreinte : %v", err)
	}
	if !strings.HasPrefix(empreinte, "SHA256:") {
		t.Fatalf("empreinte %q : préfixe SHA256: attendu", empreinte)
	}
	// SHA-256 sur 32 octets → 43 caractères en base64 sans remplissage.
	corps := strings.TrimPrefix(empreinte, "SHA256:")
	if len(corps) != 43 {
		t.Fatalf("corps de %d caractères, attendu 43 : %q", len(corps), corps)
	}
	if strings.Contains(corps, "=") {
		t.Fatalf("remplissage base64 présent : %q", empreinte)
	}
}

// TestEntreeIllisibleRefusee : un PEM invalide ne doit pas passer pour une clé.
func TestEntreeIllisibleRefusee(t *testing.T) {
	for _, entree := range []string{"", "pas du PEM", "-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n"} {
		if _, err := EmpreinteClePublique(entree); err == nil {
			t.Errorf("entrée %q acceptée comme clé publique", entree)
		}
	}
}

// TestEmpreinteToleranteAuFichier : commentaires, espaces, saut final.
//
// Le fichier est destiné à être lu et parfois édité par un administrateur.
// S'il refusait un commentaire ou une ligne vide, la vérification tomberait
// silencieusement — EmpreinteAttendue rendrait "" et l'agent repasserait en
// confiance aveugle, ce qui est exactement le contraire du but.
func TestEmpreinteToleranteAuFichier(t *testing.T) {
	dir := repertoireDeTest(t)
	attendue := "SHA256:" + strings.Repeat("A", 43)

	contenus := map[string]string{
		"nue":                  attendue,
		"avec saut":            attendue + "\n",
		"avec commentaire":     "# posée le 8 août\n" + attendue + "\n",
		"avec ligne vide":      "\n\n" + attendue + "\n",
		"avec espaces":         "   " + attendue + "   \n",
		"terminaisons Windows": "# note\r\n" + attendue + "\r\n",
	}

	for nom, contenu := range contenus {
		t.Run(nom, func(t *testing.T) {
			chemin := filepath.Join(dir, FingerprintFileName)
			if err := os.WriteFile(chemin, []byte(contenu), 0o644); err != nil {
				t.Fatalf("écriture : %v", err)
			}
			lue, err := EmpreinteAttendue()
			if err != nil {
				t.Fatalf("lecture : %v", err)
			}
			if lue != attendue {
				t.Fatalf("empreinte lue %q, attendue %q — la vérification serait désactivée", lue, attendue)
			}
		})
	}
}

// TestEcrireEmpreinteRefuseUneFormeInvalide : mieux vaut refuser à l'écriture
// qu'écrire une valeur qui ne correspondra jamais à rien.
func TestEcrireEmpreinteRefuseUneFormeInvalide(t *testing.T) {
	repertoireDeTest(t)
	for _, mauvaise := range []string{"", "abcdef", "MD5:xxx", "sha256:minuscules"} {
		if err := EcrireEmpreinte(mauvaise); err == nil {
			t.Errorf("empreinte %q écrite alors qu'elle est mal formée", mauvaise)
		}
	}
}

// --- La clé DÉJÀ présente sur le disque -------------------------------------
//
// Ces tests reproduisent une panne observée sur une machine réelle : un
// `serveurpublickey.pem` obtenu d'un core dont la clé avait changé depuis.
//
// L'agent chiffrait sa poignée de main avec une clé que le core ne pouvait plus
// déchiffrer. Le core n'y répondait pas ; l'agent attendait puis signalait
// « Erreur lors de la lecture du header : EOF » — un message qui ne désigne
// rien, alors que l'empreinte était sur la machine, à côté du fichier fautif.
//
// La première version du contrôle ne vérifiait qu'à la RÉCEPTION de la clé,
// donc jamais celles déjà en place. Or ce sont exactement celles dont on ne
// sait rien.

func poserCleLocale(t *testing.T, dir, pemContent string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "serveurpublickey.pem"), []byte(pemContent), 0o644); err != nil {
		t.Fatalf("écriture de la clé locale : %v", err)
	}
}

// TestCleLocalePerimeeEstDetectee est le test de la panne observée.
func TestCleLocalePerimeeEstDetectee(t *testing.T) {
	dir := repertoireDeTest(t)

	cleDuCoreActuel := clePubliquePEM(t)
	cleAncienne := clePubliquePEM(t)

	empreinte, err := EmpreinteClePublique(cleDuCoreActuel)
	if err != nil {
		t.Fatalf("empreinte : %v", err)
	}
	if err := EcrireEmpreinte(empreinte); err != nil {
		t.Fatalf("écriture de l'empreinte : %v", err)
	}
	poserCleLocale(t, dir, cleAncienne)

	aEcarter, motif := CleLocaleConforme()
	if !aEcarter {
		t.Fatal("une clé locale ne correspondant pas à l'empreinte n'est pas détectée : " +
			"l'agent partirait avec, et échouerait sur un EOF sans cause identifiable")
	}
	// Le motif doit contenir les deux empreintes et la marche à suivre.
	for _, attendu := range []string{empreinte, "vlt certificate fingerprint"} {
		if !strings.Contains(motif, attendu) {
			t.Errorf("le motif ne contient pas %q", attendu)
		}
	}
}

// TestCleLocaleConformeEstConservee : ne pas jeter une clé valide.
//
// Sans ce test, un code qui écarterait TOUTES les clés passerait le précédent
// tout en provoquant un askkey à chaque connexion.
func TestCleLocaleConformeEstConservee(t *testing.T) {
	dir := repertoireDeTest(t)

	cle := clePubliquePEM(t)
	empreinte, err := EmpreinteClePublique(cle)
	if err != nil {
		t.Fatalf("empreinte : %v", err)
	}
	if err := EcrireEmpreinte(empreinte); err != nil {
		t.Fatalf("écriture : %v", err)
	}
	poserCleLocale(t, dir, cle)

	if aEcarter, motif := CleLocaleConforme(); aEcarter {
		t.Fatalf("une clé conforme est écartée : %s", motif)
	}
}

// TestCleLocaleSansEmpreinteEstConservee.
//
// Sans empreinte, il n'y a rien à quoi comparer. Écarter une clé qu'on ne peut
// pas remplacer par mieux ne ferait qu'ouvrir la porte au premier venu.
func TestCleLocaleSansEmpreinteEstConservee(t *testing.T) {
	dir := repertoireDeTest(t)
	poserCleLocale(t, dir, clePubliquePEM(t))

	if aEcarter, motif := CleLocaleConforme(); aEcarter {
		t.Fatalf("clé écartée alors qu'aucune empreinte ne permet d'en juger : %s", motif)
	}
}

// TestAbsenceDeCleLocaleNestPasUneAnomalie : le chemin d'une première connexion.
func TestAbsenceDeCleLocaleNestPasUneAnomalie(t *testing.T) {
	repertoireDeTest(t)
	empreinte, err := EmpreinteClePublique(clePubliquePEM(t))
	if err != nil {
		t.Fatalf("empreinte : %v", err)
	}
	if err := EcrireEmpreinte(empreinte); err != nil {
		t.Fatalf("écriture : %v", err)
	}

	if aEcarter, motif := CleLocaleConforme(); aEcarter {
		t.Fatalf("clé absente signalée comme à écarter : %s", motif)
	}
}

// TestCleLocaleIllisibleEstEcartee : un fichier tronqué ne servira à rien.
func TestCleLocaleIllisibleEstEcartee(t *testing.T) {
	dir := repertoireDeTest(t)
	empreinte, err := EmpreinteClePublique(clePubliquePEM(t))
	if err != nil {
		t.Fatalf("empreinte : %v", err)
	}
	if err := EcrireEmpreinte(empreinte); err != nil {
		t.Fatalf("écriture : %v", err)
	}
	poserCleLocale(t, dir, "-----BEGIN RSA PUBLIC KEY-----\ntronqu")

	if aEcarter, _ := CleLocaleConforme(); !aEcarter {
		t.Fatal("une clé illisible est conservée : l'agent repartirait avec un fichier inutilisable")
	}
}

// TestEcarterCleLocale : la suppression, et son idempotence.
func TestEcarterCleLocale(t *testing.T) {
	dir := repertoireDeTest(t)
	poserCleLocale(t, dir, clePubliquePEM(t))

	if err := EcarterCleLocale(); err != nil {
		t.Fatalf("suppression : %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "serveurpublickey.pem")); !os.IsNotExist(err) {
		t.Fatal("la clé est encore là après EcarterCleLocale")
	}
	// Deuxième appel : ne doit pas échouer sur un fichier déjà absent.
	if err := EcarterCleLocale(); err != nil {
		t.Fatalf("second appel en erreur alors que le fichier est déjà absent : %v", err)
	}
}

// TestRepriseApresCleEcartee vérifie l'enchaînement complet.
//
// C'est le scénario de bout en bout : clé périmée détectée, écartée, puis la
// clé légitime du core est acceptée parce qu'elle correspond à l'empreinte.
func TestRepriseApresCleEcartee(t *testing.T) {
	dir := repertoireDeTest(t)

	cleActuelle := clePubliquePEM(t)
	empreinte, err := EmpreinteClePublique(cleActuelle)
	if err != nil {
		t.Fatalf("empreinte : %v", err)
	}
	if err := EcrireEmpreinte(empreinte); err != nil {
		t.Fatalf("écriture : %v", err)
	}
	poserCleLocale(t, dir, clePubliquePEM(t)) // une autre clé : périmée

	aEcarter, _ := CleLocaleConforme()
	if !aEcarter {
		t.Fatal("clé périmée non détectée")
	}
	if err := EcarterCleLocale(); err != nil {
		t.Fatalf("suppression : %v", err)
	}

	// L'agent redemande. La clé légitime doit passer.
	if _, err := VerifierCleCore(cleActuelle); err != nil {
		t.Fatalf("la clé légitime du core est refusée après reprise : %v", err)
	}

	// Et un imposteur doit toujours être refusé — c'est ce qui rend la reprise
	// automatique acceptable.
	if _, err := VerifierCleCore(clePubliquePEM(t)); err == nil {
		t.Fatal("une clé étrangère est acceptée après reprise : " +
			"écarter la clé locale reviendrait alors à ouvrir la porte")
	}
}

// TestAllerRetour : ce que le core écrit, l'agent le lit et l'accepte.
//
// Les deux moitiés vivent dans des modules Go différents et ne se compilent
// jamais ensemble ; c'est précisément pour cela qu'il faut vérifier qu'elles
// s'accordent.
func TestAllerRetour(t *testing.T) {
	repertoireDeTest(t)

	cle := clePubliquePEM(t)
	empreinte, err := EmpreinteClePublique(cle)
	if err != nil {
		t.Fatalf("empreinte : %v", err)
	}
	if err := EcrireEmpreinte(empreinte); err != nil {
		t.Fatalf("écriture : %v", err)
	}
	if _, err := VerifierCleCore(cle); err != nil {
		t.Fatalf("la clé écrite puis relue est refusée : %v", err)
	}
}
