package gpo

import (
	"strings"
	"testing"
)

// TO-DO 211 : les marqueurs par compte.

func TestRemplacerMarqueurs(t *testing.T) {
	id := &Identite{NomComplet: "Alice Martin", Mail: "alice.martin@acme.lan", Domaine: "infra.acme.lan"}
	cas := []struct{ compte, v, attendu string }{
		{"alice@acme.lan", "%u", "alice"},
		{"alice@acme.lan", "%U", "alice@acme.lan"},
		{"alice@acme.lan", "%d", "acme.lan"},
		{"alice", "%U", "alice@infra.acme.lan"}, // domaine de l'identité
		{"alice@acme.lan", "%n <%m>", "Alice Martin <alice.martin@acme.lan>"},
		{"alice@acme.lan", "100%%", "100%"},
		{"alice@acme.lan", "sans marqueur", "sans marqueur"},
	}
	for _, c := range cas {
		obtenu, err := remplacerMarqueurs(c.v, c.compte, id)
		if err != nil || obtenu != c.attendu {
			t.Errorf("%q pour %s = %q, %v ; attendu %q", c.v, c.compte, obtenu, err, c.attendu)
		}
	}
	// Un marqueur inconnu est LAISSÉ tel quel : `%h` est un format de git, et
	// une politique d'avant le 211 peut en porter (le core les refuse désormais).
	for _, v := range []string{"%x", "fin%", "log %h %s"} {
		if obtenu, err := remplacerMarqueurs(v, "alice@acme.lan", id); err != nil || obtenu != v {
			t.Errorf("%q → %q, %v : attendu inchangé", v, obtenu, err)
		}
	}
	if _, err := remplacerMarqueurs("%n", "alice@acme.lan", nil); err == nil {
		t.Error("%n sans identité livrée : accepté")
	}
}

// La liste est la même que celle du core (core/gpo/marqueurs.go) : un
// marqueur accepté à l'enregistrement doit l'être sur le poste.
func TestLesMarqueursSontCeuxDuCore(t *testing.T) {
	id := &Identite{NomComplet: "N", Mail: "m@x", Domaine: "d"}
	for _, c := range "uUdnm%" {
		if _, err := remplacerMarqueurs("%"+string(c), "a@b", id); err != nil {
			t.Errorf("%%%c refusé par l'agent : %v", c, err)
		}
	}
}

func TestDevelopperMarqueursDansUnePolitiqueDeCompte(t *testing.T) {
	p := &Policy{Scope: ScopeUser, Username: "alice@acme.lan",
		Identite: &Identite{NomComplet: "Alice Martin", Mail: "alice@acme.lan"},
		Modules: []Module{
			{Type: ModuleUserGitConfig, StateKey: "git:user.name", Fingerprint: "fp1",
				Params: map[string]string{"key": "user.name", "value": "%n"}},
			{Type: ModuleUserGitConfig, StateKey: "git:pull.rebase", Fingerprint: "fp2",
				Params: map[string]string{"key": "pull.rebase", "value": "true"}},
			{Type: ModuleUserEnv, StateKey: "env:X", Fingerprint: "fp3",
				Params: map[string]string{"name": "X", "value": "%z"}},
		}}
	erreurs := developperMarqueurs(p)

	if v := p.Modules[0].Params["value"]; v != "Alice Martin" {
		t.Errorf("user.name = %q", v)
	}
	if !strings.HasPrefix(p.Modules[0].Fingerprint, "fp1+") {
		t.Errorf("empreinte sans suffixe : %q — un renommage ne rejouerait pas le module", p.Modules[0].Fingerprint)
	}
	if p.Modules[1].Fingerprint != "fp2" {
		t.Errorf("module sans marqueur : empreinte changée (%q)", p.Modules[1].Fingerprint)
	}
	if v := p.Modules[2].Params["value"]; v != "%z" || len(erreurs) != 0 {
		t.Errorf("marqueur inconnu : %q, erreurs %v — attendu laissé tel quel", v, erreurs)
	}

	// Un autre nom complet : une autre empreinte.
	q := &Policy{Scope: ScopeUser, Username: "alice@acme.lan", Identite: &Identite{NomComplet: "Alice Durand"},
		Modules: []Module{{Type: ModuleUserGitConfig, StateKey: "git:user.name", Fingerprint: "fp1",
			Params: map[string]string{"key": "user.name", "value": "%n"}}}}
	developperMarqueurs(q)
	if q.Modules[0].Fingerprint == p.Modules[0].Fingerprint {
		t.Error("nom complet changé, empreinte identique")
	}

	// La portée machine n'est jamais touchée.
	m := &Policy{Scope: ScopeMachine, Modules: []Module{{Type: ModuleUserEnv, StateKey: "e", Fingerprint: "f",
		Params: map[string]string{"value": "%n"}}}}
	developperMarqueurs(m)
	if m.Modules[0].Params["value"] != "%n" {
		t.Error("portée machine modifiée")
	}
}
