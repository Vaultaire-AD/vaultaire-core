package gpo

import "testing"

// TO-DO 211 : un marqueur inconnu est refusé à l'enregistrement.
func TestVerifierMarqueurs(t *testing.T) {
	bons := []string{"", "Alice", "%n", "%u@exemple.fr", "%U", "%d", "%m", "100%%", "%n <%m>"}
	for _, v := range bons {
		if err := VerifierMarqueurs(v); err != nil {
			t.Errorf("%q refusé : %v", v, err)
		}
	}
	mauvais := []string{"%x", "100%", "%h", "a%Zb"}
	for _, v := range mauvais {
		if err := VerifierMarqueurs(v); err == nil {
			t.Errorf("%q accepté", v)
		}
	}
}

// Le refus passe par la validation d'un module : user_git_config, user_env.
func TestUnModuleDeCompteRefuseUnMarqueurInconnu(t *testing.T) {
	m := Module{Type: ModuleUserGitConfig, Params: map[string]string{
		"key": "user.name", "value": "%z", "state": "present"}}
	if _, err := ValidateModule(ScopeUser, m); err == nil {
		t.Error("user_git_config : marqueur inconnu accepté")
	}
	m.Params["value"] = "%n"
	if _, err := ValidateModule(ScopeUser, m); err != nil {
		t.Errorf("user_git_config : %%n refusé : %v", err)
	}
	e := Module{Type: ModuleUserEnv, Params: map[string]string{"name": "GIT_AUTHOR", "value": "%q"}}
	if _, err := ValidateModule(ScopeUser, e); err == nil {
		t.Error("user_env : marqueur inconnu accepté")
	}
}
