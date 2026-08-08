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

	store "vaultaire_client/storage"
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
	ancien := store.KeyPath
	store.KeyPath = dir
	t.Cleanup(func() { store.KeyPath = ancien })
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
