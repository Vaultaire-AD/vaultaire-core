package ldapbindunbind

import (
	"testing"
	"time"
)

func TestSeparerCode(t *testing.T) {
	cas := []struct {
		entree, mdp, code string
		ok                bool
	}{
		{"MonMotDePasse123456", "MonMotDePasse", "123456", true},
		{"a000000", "a", "000000", true},
		{"123456", "", "", false},           // pas de mot de passe
		{"MotDePasse12345a", "", "", false}, // ne finit pas par 6 chiffres
		{"court", "", "", false},
	}
	for _, c := range cas {
		mdp, code, ok := separerCode(c.entree)
		if ok != c.ok || mdp != c.mdp || code != c.code {
			t.Errorf("separerCode(%q) = %q, %q, %v ; attendu %q, %q, %v", c.entree, mdp, code, ok, c.mdp, c.code, c.ok)
		}
	}
}

func TestVerifierCodeRefuseLeRejeu(t *testing.T) {
	ancV, ancC := validerTOTP, consommerCompteur
	defer func() { validerTOTP, consommerCompteur = ancV, ancC }()

	validerTOTP = func(secret, code string, _ time.Time) (int64, bool) { return 42, code == "123456" }
	consommes := map[int64]bool{}
	consommerCompteur = func(_ string, c int64) (bool, error) {
		if consommes[c] {
			return false, nil
		}
		consommes[c] = true
		return true, nil
	}

	if r := verifierCode("alice", "S", "000000"); r == "" {
		t.Fatal("un code faux est accepté")
	}
	if r := verifierCode("alice", "S", "123456"); r != "" {
		t.Fatalf("code valide refusé : %s", r)
	}
	if r := verifierCode("alice", "S", "123456"); r == "" {
		t.Fatal("un code rejoué est accepté")
	}
}
