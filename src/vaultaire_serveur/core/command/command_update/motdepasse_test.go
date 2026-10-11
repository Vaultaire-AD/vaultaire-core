package commandupdate

import "testing"

// update -u … -p : le drapeau --permanent (TO-DO 144).
func TestParamsChangementMotDePasse(t *testing.T) {
	cas := []struct {
		args            []string
		mdp, temporaire string
		refuse          bool
	}{
		{[]string{"-u", "bob", "-p", "une", "phrase", "de", "passe"}, "une phrase de passe", "", false},
		{[]string{"-u", "svc_keycloak", "--permanent", "-p", "Ancre-Violon-Galet-91"}, "Ancre-Violon-Galet-91", "non", false},
		{[]string{"-u", "svc", "--PERMANENT", "-p", "x y"}, "x y", "non", false},
		// APRÈS -p, le drapeau fait partie du mot de passe : jamais pris pour
		// une dérogation, que personne n'aurait demandée.
		{[]string{"-u", "bob", "-p", "abc", "--permanent"}, "abc --permanent", "", false},
		{[]string{"-u", "bob", "--permanent"}, "", "", true},
		{[]string{"-u", "bob", "-x", "abc"}, "", "", true},
	}
	for _, c := range cas {
		p, ok := ParamsChangementMotDePasse(c.args)
		if c.refuse {
			if ok {
				t.Errorf("%v accepté", c.args)
			}
			continue
		}
		if !ok || p["password"] != c.mdp || p["temporary"] != c.temporaire {
			t.Errorf("%v -> %v (ok %v), attendu mdp %q temporary %q", c.args, p, ok, c.mdp, c.temporaire)
		}
	}
}
