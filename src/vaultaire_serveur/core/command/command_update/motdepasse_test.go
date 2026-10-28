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
		// APRÈS -p, en dernier mot : refusé — il aurait fini dans le mot de
		// passe sans que personne le sache (recette du 28/10).
		{[]string{"-u", "bob", "-p", "abc", "--permanent"}, "", "", true},
		// Tel que le découpage de la console le livre : « --permanent » puis
		// « -p <mot de passe> » en UN argument.
		{[]string{"-u", "bob", "--permanent", "-p Cerf-Volant 58"}, "Cerf-Volant 58", "non", false},
		{[]string{"-u", "bob", "-p", "abc --permanent def"}, "abc --permanent def", "", false},
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
