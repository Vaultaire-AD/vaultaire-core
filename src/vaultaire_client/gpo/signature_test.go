package gpo

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"duckynetworkclient/V1/duckynetwork/storage"
)

// La signature n'a de valeur que si elle est VÉRIFIÉE, et refusée quand elle ne
// correspond pas. Un mécanisme qui accepte tout produit l'apparence de la
// sécurité sans la sécurité — ces tests sont là pour cela.

// paireDeTest fabrique une clé et son fichier PEM, comme le core les dépose.
func paireDeTest(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	// 2048 et non 4096 : c'est un test, et la génération d'une 4096 coûte
	// plusieurs secondes par appel.
	clef, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&clef.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	fichier := append([]byte("# Clé publique de signature des politiques.\n"),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})...)
	return clef, fichier
}

// avecCleDeployee pose le fichier de clé là où l'agent le cherche.
func avecCleDeployee(t *testing.T, fichier []byte) {
	t.Helper()
	dir := t.TempDir()
	if fichier != nil {
		if err := os.WriteFile(filepath.Join(dir, NomFichierCleSignature), fichier, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	ancien := storage.KeyPath
	storage.KeyPath = dir
	oublierCle()
	t.Cleanup(func() {
		storage.KeyPath = ancien
		oublierCle()
	})
}

// signerPourTest reproduit exactement ce que fait le core.
func signerPourTest(t *testing.T, clef *rsa.PrivateKey, corps string) string {
	t.Helper()
	condense := sha256.Sum256([]byte(corps))
	sig, err := rsa.SignPSS(rand.Reader, clef, crypto.SHA256, condense[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	})
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

// Le corps signé est composé des deux côtés du réseau, et rien ne lie les deux
// implémentations à la compilation. Une divergence d'un octet ferait refuser
// toutes les politiques du parc.
func TestLeCorpsSigneNeChangePas(t *testing.T) {
	attendu := "vaultaire-gpo-v1\nposte-42\nmachine\n\nempreinte\nsomme"
	if got := CorpsSigne("poste-42", "machine", "", "empreinte", "somme"); got != attendu {
		t.Errorf("corps signé =\n%q\nattendu\n%q\n(la composition est jumelle de "+
			"keymanagement.CorpsSigne côté core)", got, attendu)
	}
}

// La séparation de domaine et la version ouvrent le corps : sans elles, la même
// clé pourrait un jour signer autre chose qui soit pris pour une politique.
func TestLeCorpsPorteSaVersion(t *testing.T) {
	if !strings.HasPrefix(CorpsSigne("a", "b", "c", "d", "e"), "vaultaire-gpo-v1\n") {
		t.Error("le corps signé ne commence pas par sa séparation de domaine")
	}
}

// Les préfixes sont déclarés des deux côtés du réseau.
func TestLesPrefixesRestentCeuxDuCore(t *testing.T) {
	if PrefixeSignature != "sig:" {
		t.Errorf("PrefixeSignature = %q : doit rester identique au core", PrefixeSignature)
	}
	if PrefixeSignatureExigee != "sigreq:" {
		t.Errorf("PrefixeSignatureExigee = %q : doit rester identique au core", PrefixeSignatureExigee)
	}
}

// Les lignes de queue se lisent AU PRÉFIXE, jamais au rang : c'est ce qui
// permet d'en ajouter sans déplacer les six champs du manifeste.
func TestLesLignesDeQueueSeLisentAuPrefixe(t *testing.T) {
	lignes := []string{
		"3", "empreinte", "2", "4096", "7", "somme",
		"refresh:60", "sig:QUJD", "sigreq:1",
	}
	sig, exigee := lireLignesSignature(lignes)
	if sig != "QUJD" {
		t.Errorf("signature = %q, attendu QUJD", sig)
	}
	if !exigee {
		t.Error("exigence non lue")
	}
}

// Un manifeste d'un core d'une version antérieure ne porte aucune de ces
// lignes : l'agent doit se comporter exactement comme avant.
func TestUnManifesteSansLigneDeQueue(t *testing.T) {
	sig, exigee := lireLignesSignature([]string{"3", "empreinte", "2", "4096", "7", "somme"})
	if sig != "" || exigee {
		t.Errorf("signature=%q exigée=%v, attendu vide et faux", sig, exigee)
	}
}

// LE test : une signature valide passe, une signature d'un AUTRE destinataire
// ne passe pas. Signer les seuls octets du document aurait laissé une politique
// valide rejouable d'une machine à l'autre.
func TestUneSignatureNEstValableQuePourSonDestinataire(t *testing.T) {
	clef, fichier := paireDeTest(t)
	avecCleDeployee(t, fichier)

	sig := signerPourTest(t, clef, CorpsSigne("poste-42", "machine", "", "emp", "som"))

	if err := VerifierSignature("poste-42", "machine", "", "emp", "som", sig, true); err != nil {
		t.Fatalf("signature valide refusée : %v", err)
	}
	if err := VerifierSignature("poste-43", "machine", "", "emp", "som", sig, false); err == nil {
		t.Error("la politique d'une machine a été acceptée par une autre")
	}
}

// Chaque champ du corps doit compter : une politique d'un autre utilisateur, ou
// portant une autre somme de contrôle, n'est pas celle qu'on a signée.
func TestChaqueChampDuCorpsCompte(t *testing.T) {
	clef, fichier := paireDeTest(t)
	avecCleDeployee(t, fichier)

	sig := signerPourTest(t, clef, CorpsSigne("poste-42", "user", "alice", "emp", "som"))

	cas := []struct {
		nom                               string
		id, scope, user, empreinte, somme string
	}{
		{"machine", "poste-99", "user", "alice", "emp", "som"},
		{"scope", "poste-42", "machine", "alice", "emp", "som"},
		{"utilisateur", "poste-42", "user", "bob", "emp", "som"},
		{"empreinte", "poste-42", "user", "alice", "autre", "som"},
		{"somme de contrôle", "poste-42", "user", "alice", "emp", "autre"},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			if err := VerifierSignature(c.id, c.scope, c.user, c.empreinte, c.somme, sig, false); err == nil {
				t.Errorf("le champ %q ne compte pas dans la signature", c.nom)
			}
		})
	}
}

// Une signature FAUSSE est refusée même sans exigence : ce n'est pas l'absence
// d'une signature, c'est un document qu'on a tenté de faire passer.
func TestUneSignatureFausseEstToujoursRefusee(t *testing.T) {
	_, fichier := paireDeTest(t)
	avecCleDeployee(t, fichier)

	autre, _ := paireDeTest(t)
	sig := signerPourTest(t, autre, CorpsSigne("poste-42", "machine", "", "emp", "som"))

	if err := VerifierSignature("poste-42", "machine", "", "emp", "som", sig, false); err == nil {
		t.Error("une signature faite avec une autre clé a été acceptée")
	}
}

// Les quatre cas de la migration, et surtout le premier : une machine installée
// avant cette version n'a pas la clé. Refuser là couperait ses GPO sans que
// l'administrateur ait rien fait ni rien vu venir.
func TestLaMigration(t *testing.T) {
	clef, fichier := paireDeTest(t)
	bonneSig := func() string {
		return signerPourTest(t, clef, CorpsSigne("poste-42", "machine", "", "emp", "som"))
	}

	t.Run("sans clé, exigence posée : la politique passe", func(t *testing.T) {
		avecCleDeployee(t, nil)
		if err := VerifierSignature("poste-42", "machine", "", "emp", "som", "", true); err != nil {
			t.Errorf("politique refusée sur une machine qui ne peut rien vérifier : %v", err)
		}
	})

	t.Run("sans clé, signature présente : la politique passe", func(t *testing.T) {
		avecCleDeployee(t, nil)
		if err := VerifierSignature("poste-42", "machine", "", "emp", "som", bonneSig(), false); err != nil {
			t.Errorf("politique refusée sans clé de vérification : %v", err)
		}
	})

	t.Run("clé, pas de signature, sans exigence : la politique passe", func(t *testing.T) {
		avecCleDeployee(t, fichier)
		if err := VerifierSignature("poste-42", "machine", "", "emp", "som", "", false); err != nil {
			t.Errorf("politique non signée refusée hors exigence : %v", err)
		}
	})

	t.Run("clé, pas de signature, exigence posée : REFUS", func(t *testing.T) {
		avecCleDeployee(t, fichier)
		if err := VerifierSignature("poste-42", "machine", "", "emp", "som", "", true); err == nil {
			t.Error("politique non signée acceptée alors que le core l'exige")
		}
	})

	t.Run("clé et bonne signature : la politique passe", func(t *testing.T) {
		avecCleDeployee(t, fichier)
		if err := VerifierSignature("poste-42", "machine", "", "emp", "som", bonneSig(), true); err != nil {
			t.Errorf("politique valide refusée : %v", err)
		}
	})
}

// Une signature illisible n'est pas une signature absente.
func TestUneSignatureIllisibleEstRefusee(t *testing.T) {
	_, fichier := paireDeTest(t)
	avecCleDeployee(t, fichier)

	for _, mauvaise := range []string{"pas du base64 !!", "QUJD"} {
		if err := VerifierSignature("poste-42", "machine", "", "emp", "som", mauvaise, false); err == nil {
			t.Errorf("signature %q acceptée", mauvaise)
		}
	}
}

// Une clé présente mais illisible ne doit pas faire croire à une vérification.
func TestUneCleIllisibleNeVerifieRien(t *testing.T) {
	avecCleDeployee(t, []byte("ceci n'est pas une clé\n"))
	if ClePolitique() != nil {
		t.Error("une clé illisible a été retenue")
	}
}

// Le fichier déposé par le core porte des lignes de commentaire avant le bloc.
func TestLeFichierDeCleAccepteLesCommentaires(t *testing.T) {
	_, fichier := paireDeTest(t)
	if _, err := LireClePublique(fichier); err != nil {
		t.Errorf("le fichier déposé par le core n'est pas lisible : %v", err)
	}
}
