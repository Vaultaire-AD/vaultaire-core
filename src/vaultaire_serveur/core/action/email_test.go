package action

import "testing"

func TestNormaliserEmail(t *testing.T) {
	bons := map[string]string{
		"alice@acme.fr":                  "alice@acme.fr",
		"  Alice.Martin@ACME.fr ":        "alice.martin@acme.fr",
		"a+tag@sous.domaine.acme.lan":    "a+tag@sous.domaine.acme.lan",
		"admin@vaultaire":                "admin@vaultaire",
		"prenom.nom-2@users.admin.local": "prenom.nom-2@users.admin.local",
	}
	for entree, attendu := range bons {
		got, err := NormaliserEmail(entree)
		if err != nil || got != attendu {
			t.Errorf("NormaliserEmail(%q) = %q, %v ; attendu %q", entree, got, err, attendu)
		}
	}
	mauvais := []string{
		"", "   ", "alice", "alice@", "@acme.fr", "alice@@acme.fr", "a@b@c.fr",
		"Alice <alice@acme.fr>", "alice @acme.fr", "alice@acme..fr", "alice@.acme.fr",
		"alice@acme.fr.", "\"a b\"@acme.fr", "alice@acme.fr\nBcc: x@y.fr",
		string(make([]byte, 255)) + "@a.fr",
	}
	for _, entree := range mauvais {
		if got, err := NormaliserEmail(entree); err == nil {
			t.Errorf("NormaliserEmail(%q) = %q : refus attendu", entree, got)
		}
	}
}
