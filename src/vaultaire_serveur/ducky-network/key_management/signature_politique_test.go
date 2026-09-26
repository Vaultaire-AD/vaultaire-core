package keymanagement

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

// Le corps signé est composé des deux côtés du réseau et rien ne les lie à la
// compilation. Une divergence d'un seul octet ferait refuser toutes les
// politiques du parc, avec un message qui ne dirait pas pourquoi.
//
// La valeur écrite ici en dur est la MÊME que dans
// vaultaire_client/gpo/signature_test.go.
func TestLeCorpsSigneNeChangePas(t *testing.T) {
	attendu := "vaultaire-gpo-v1\nposte-42\nmachine\n\nempreinte\nsomme"
	if got := CorpsSigne("poste-42", "machine", "", "empreinte", "somme"); got != attendu {
		t.Errorf("corps signé =\n%q\nattendu\n%q\n(la composition est jumelle de "+
			"gpo.CorpsSigne côté agent)", got, attendu)
	}
}

// Les espaces autour des champs sont rognés des deux côtés : un identifiant de
// machine recopié avec un espace ne doit pas produire une signature que l'agent
// refusera sans savoir pourquoi.
func TestLesChampsSontRognes(t *testing.T) {
	avec := CorpsSigne(" poste-42 ", " machine ", "  ", " emp ", " som ")
	sans := CorpsSigne("poste-42", "machine", "", "emp", "som")
	if avec != sans {
		t.Errorf("les espaces changent le corps signé :\n%q\n%q", avec, sans)
	}
}

// La vérification que fait l'agent, reproduite ici sur une signature produite
// par le code du core : c'est le seul endroit où les deux moitiés se rencontrent
// sans réseau.
func TestUneSignatureDuCoreEstVerifiableParLAgent(t *testing.T) {
	clef, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	corps := CorpsSigne("poste-42", "user", "alice", "emp", "som")
	condense := sha256.Sum256([]byte(corps))

	sig, err := rsa.SignPSS(rand.Reader, clef, crypto.SHA256, condense[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	})
	if err != nil {
		t.Fatal(err)
	}

	// L'agent décode du base64 puis vérifie en PSS SHA-256 : si l'un des deux
	// côtés changeait de bourrage ou de condensat, ce test tomberait.
	brute, err := base64.StdEncoding.DecodeString(base64.StdEncoding.EncodeToString(sig))
	if err != nil {
		t.Fatal(err)
	}
	if err := rsa.VerifyPSS(&clef.PublicKey, crypto.SHA256, condense[:], brute, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	}); err != nil {
		t.Fatalf("signature du core refusée par la vérification de l'agent : %v", err)
	}
}

// Sans base, la signature échoue PROPREMENT : elle ne doit ni paniquer, ni
// rendre une chaîne vide qui passerait pour une signature.
func TestSansBaseLaSignatureEchoueProprement(t *testing.T) {
	sig, err := SignerLivraison("poste-42", "machine", "", "emp", "som")
	if err == nil {
		t.Fatal("aucune erreur alors que la base est absente")
	}
	if sig != "" {
		t.Errorf("signature rendue malgré l'erreur : %q", sig)
	}
}

// Une clé privée illisible est une erreur, pas une panique : ce chemin est
// traversé à chaque livraison de politique.
func TestUneClePriveeIllisibleEstUneErreur(t *testing.T) {
	for _, contenu := range []string{"", "pas du PEM", "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----"} {
		if _, err := LireClePriveePEM(contenu); err == nil {
			t.Errorf("clé %q acceptée", contenu)
		}
	}
}
