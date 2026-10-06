package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"vaultaire/core/auth/ratelimit"
	"vaultaire/core/permission"
	"vaultaire/core/storage"

	"golang.org/x/crypto/ssh"
)

// Les bornes de /api/command (TO-DO 102).
//
// # Ce que ces tests gardent
//
//   - le corps est borné, et un corps trop gros ne coûte aucune lecture en base ;
//   - une source qui inonde, ou qui échoue en boucle, est refusée AVANT la base ;
//   - compte inconnu, révoqué, sans clé, signature fausse : même statut, même
//     message, même parcours — le nom d'un compte ne se devine plus à la réponse.

type banc struct {
	t        *testing.T
	alice    ssh.Signer
	autre    ssh.Signer
	lectures int // appels à chercherCles : le travail fait en base
	comptes  int // appels à chercherCompte
	cles     map[int][]storage.PublicKey
}

func nouveauBanc(t *testing.T) *banc {
	t.Helper()
	b := &banc{t: t, alice: signataire(t), autre: signataire(t)}
	b.cles = map[int][]storage.PublicKey{
		7: {{ID: 1, UserID: 7, Key: string(ssh.MarshalAuthorizedKey(b.alice.PublicKey()))}},
		8: nil, // « bob » existe mais n'a aucune clé
	}

	ratelimit.Reinitialiser()
	ancienDebit, ancienCompte, ancienCles := debitAPI, chercherCompte, chercherCles
	debitAPI = ratelimit.NouveauDebit("test", 1000, 1000)
	chercherCompte = func(nom string) (int, error) {
		b.comptes++
		switch nom {
		case "alice":
			return 7, nil
		case "bob":
			return 8, nil
		}
		return 0, fmt.Errorf("utilisateur %q introuvable", nom)
	}
	chercherCles = func(id int) ([]storage.PublicKey, error) {
		b.lectures++
		return b.cles[id], nil
	}
	t.Cleanup(func() {
		debitAPI, chercherCompte, chercherCles = ancienDebit, ancienCompte, ancienCles
		permission.SetRevokedChecker(nil)
		ratelimit.Reinitialiser()
	})
	return b
}

func signataire(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// corps fabrique une requête signée comme le fait `vlt`.
func (b *banc) corps(signer ssh.Signer, nom string, horodatage time.Time) []byte {
	b.t.Helper()
	req := &CommandRequest{
		Username:  nom,
		Command:   "status",
		Nonce:     fmt.Sprintf("n-%d", time.Now().UnixNano()),
		Timestamp: horodatage.Unix(),
	}
	signe, err := buildSignedBody(req)
	if err != nil {
		b.t.Fatal(err)
	}
	sig, err := signer.Sign(rand.Reader, signe)
	if err != nil {
		b.t.Fatal(err)
	}
	req.Signature = base64.StdEncoding.EncodeToString(ssh.Marshal(sig))
	out, _ := json.Marshal(req)
	return out
}

func envoyer(corps []byte, source string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/api/command", bytes.NewReader(corps))
	r.RemoteAddr = source + ":40000"
	w := httptest.NewRecorder()
	commandHandler(w, r)
	return w
}

func TestUnCorpsTropGrosEstRefuseSansToucherLaBase(t *testing.T) {
	b := nouveauBanc(t)
	gros := []byte(`{"username":"alice","command":"` + strings.Repeat("a", tailleMaxCorps) + `"}`)
	w := envoyer(gros, "10.0.0.1")
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("statut %d, attendu 413", w.Code)
	}
	if b.comptes+b.lectures != 0 {
		t.Errorf("%d lecture(s) en base pour un corps refusé", b.comptes+b.lectures)
	}
}

func TestLesRefusDAuthentificationSontIndiscernables(t *testing.T) {
	b := nouveauBanc(t)
	permission.SetRevokedChecker(func(nom string) bool { return nom == "carole" })
	b.cles[9] = b.cles[7]
	ancien := chercherCompte
	chercherCompte = func(nom string) (int, error) {
		if nom == "carole" {
			b.comptes++
			return 9, nil
		}
		return ancien(nom)
	}

	cas := map[string][]byte{
		"compte inconnu":   b.corps(b.alice, "personne", time.Now()),
		"signature fausse": b.corps(b.autre, "alice", time.Now()),
		"compte sans clé":  b.corps(b.alice, "bob", time.Now()),
		// La révocation ne se lit pas non plus à la réponse : le compte est
		// réel, la signature juste, et la réponse est celle d'un inconnu.
		"compte révoqué": b.corps(b.alice, "carole", time.Now()),
	}
	var reference string
	i := 0
	for nom, corps := range cas {
		i++
		avant := b.lectures
		w := envoyer(corps, fmt.Sprintf("10.0.1.%d", i))
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s : statut %d, attendu 401", nom, w.Code)
		}
		if reference == "" {
			reference = w.Body.String()
		} else if w.Body.String() != reference {
			t.Errorf("%s : réponse %q, différente de %q — elle dit pourquoi", nom, w.Body.String(), reference)
		}
		if b.lectures != avant+1 {
			t.Errorf("%s : %d lecture(s) de clés, attendu 1 — le parcours diffère", nom, b.lectures-avant)
		}
	}
	if !strings.Contains(reference, messageRefus) {
		t.Errorf("réponse %q, attendu %q", reference, messageRefus)
	}
}

func TestLesEchecsRepetesFreinentLaSourceAvantLaBase(t *testing.T) {
	b := nouveauBanc(t)
	for i := 0; i <= ratelimit.EssaisGratuits; i++ {
		if w := envoyer(b.corps(b.autre, "alice", time.Now()), "10.0.2.1"); w.Code != http.StatusUnauthorized {
			t.Fatalf("échec %d : statut %d, attendu 401", i+1, w.Code)
		}
	}
	avant := b.comptes
	w := envoyer(b.corps(b.alice, "alice", time.Now()), "10.0.2.1")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("statut %d après %d échecs, attendu 429", w.Code, ratelimit.EssaisGratuits+1)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("429 sans Retry-After : le client ne sait pas quand revenir")
	}
	if b.comptes != avant {
		t.Error("la requête freinée a quand même cherché le compte en base")
	}
	// Une autre source n'est pas touchée.
	if w := envoyer(b.corps(b.autre, "alice", time.Now()), "10.0.2.2"); w.Code != http.StatusUnauthorized {
		t.Errorf("autre source : statut %d, attendu 401", w.Code)
	}
}

func TestLeDebitFreineAvantLaBase(t *testing.T) {
	b := nouveauBanc(t)
	debitAPI = ratelimit.NouveauDebit("test", 2, 0.001)
	envoyer([]byte(`{}`), "10.0.3.1")
	envoyer([]byte(`{}`), "10.0.3.1")
	avant := b.comptes + b.lectures
	w := envoyer(b.corps(b.alice, "alice", time.Now()), "10.0.3.1")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("statut %d au-delà du débit, attendu 429", w.Code)
	}
	if b.comptes+b.lectures != avant {
		t.Errorf("%d lecture(s) en base au-delà du débit", b.comptes+b.lectures-avant)
	}
}

func TestUneSignatureJusteEffaceLesEchecsDeLaSource(t *testing.T) {
	b := nouveauBanc(t)
	envoyer(b.corps(b.autre, "alice", time.Now()), "10.0.4.1")
	envoyer(b.corps(b.autre, "alice", time.Now()), "10.0.4.1")
	if _, n := ratelimit.Etat("", "10.0.4.1"); n != 2 {
		t.Fatalf("%d échec(s) comptés pour la source, attendu 2", n)
	}

	// Signature juste, horodatage périmé : l'authentification passe, la
	// fraîcheur refuse — et ce refus-là n'est pas un échec d'authentification.
	w := envoyer(b.corps(b.alice, "alice", time.Now().Add(-time.Hour)), "10.0.4.1")
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "Requête rejetée") {
		t.Fatalf("statut %d, corps %q : attendu le refus de fraîcheur", w.Code, w.Body.String())
	}
	if _, n := ratelimit.Etat("", "10.0.4.1"); n != 0 {
		t.Errorf("%d échec(s) encore comptés après une signature juste", n)
	}
}

func TestUnLeurreExistePourChaqueTypeDeCle(t *testing.T) {
	for _, format := range []string{
		ssh.KeyAlgoRSA, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoED25519,
		ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
	} {
		if leurrePour(format) == nil {
			t.Errorf("aucun leurre pour %s : ce compte inconnu répondrait plus vite qu'un vrai", format)
		}
	}
	if leurrePour("inconnu") != nil {
		t.Error("un leurre pour un format inconnu")
	}
}
