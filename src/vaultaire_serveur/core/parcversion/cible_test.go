package parcversion

import "testing"

func TestNormaliserCible(t *testing.T) {
	bons := map[string]string{
		"2.3.1":   "2.3.1",
		"v2.3.1":  "2.3.1",
		" 2.3.1 ": "2.3.1",
		"02.3.1":  "2.3.1",
	}
	for saisie, attendu := range bons {
		got, err := NormaliserCible(saisie)
		if err != nil || got != attendu {
			t.Errorf("NormaliserCible(%q) = %q, %v ; attendu %q", saisie, got, err, attendu)
		}
	}
	// Une CONSIGNE ne se devine pas : pré-version, build, triplet incomplet.
	for _, saisie := range []string{"", "2.3", "2.3.1-rc1", "2.3.1+g123", "2.3.1 (x)", "dev", "none", "2.3.1.4"} {
		if got, err := NormaliserCible(saisie); err == nil {
			t.Errorf("NormaliserCible(%q) = %q accepté, refus attendu", saisie, got)
		}
	}
}

func TestEstEffacement(t *testing.T) {
	for _, s := range []string{"none", "NONE", "--none", " none "} {
		if !EstEffacement(s) {
			t.Errorf("EstEffacement(%q) = faux", s)
		}
	}
	for _, s := range []string{"", "2.3.1", "-none", "aucune"} {
		if EstEffacement(s) {
			t.Errorf("EstEffacement(%q) = vrai", s)
		}
	}
}

func TestResoudre(t *testing.T) {
	cas := []struct {
		nom    string
		c      Cibles
		def    bool
		v      string
		source Source
		groupe string
	}{
		{nom: "rien posé : aucune cible", c: Cibles{}},
		{nom: "groupes sans cible : aucune cible",
			c: Cibles{Groupes: map[string]string{"a": "", "b": " "}}},
		{nom: "défaut du parc seul", c: Cibles{Parc: "2.3.0"},
			def: true, v: "2.3.0", source: SourceParc},
		{nom: "le groupe l'emporte sur le parc, même plus bas",
			c:   Cibles{Parc: "2.4.0", Groupes: map[string]string{"general": "2.3.0"}},
			def: true, v: "2.3.0", source: SourceGroupe, groupe: "general"},
		{nom: "la plus haute des cibles de groupe",
			c:   Cibles{Groupes: map[string]string{"general": "2.3.0", "pilote": "2.4.1", "vide": ""}},
			def: true, v: "2.4.1", source: SourceGroupe, groupe: "pilote"},
		{nom: "à égalité, le premier nom dans l'ordre",
			c:   Cibles{Groupes: map[string]string{"zeta": "2.4.0", "alpha": "2.4.0"}},
			def: true, v: "2.4.0", source: SourceGroupe, groupe: "alpha"},
		{nom: "la dérogation l'emporte, même plus basse",
			c:   Cibles{Derogation: "2.2.0", Groupes: map[string]string{"pilote": "2.4.1"}, Parc: "2.4.1"},
			def: true, v: "2.2.0", source: SourceMachine},
		{nom: "dérogation illisible : aucune cible, pas celle du groupe",
			c:      Cibles{Derogation: "2.2", Groupes: map[string]string{"pilote": "2.4.1"}},
			source: SourceMachine},
		{nom: "groupe illisible écarté, l'autre compte",
			c:   Cibles{Groupes: map[string]string{"casse": "n'importe", "general": "2.3.0"}},
			def: true, v: "2.3.0", source: SourceGroupe, groupe: "general"},
		{nom: "seul groupe illisible : on retombe sur le parc",
			c:   Cibles{Groupes: map[string]string{"casse": "2.3"}, Parc: "2.3.0"},
			def: true, v: "2.3.0", source: SourceParc},
		{nom: "parc illisible : aucune cible", c: Cibles{Parc: "x"}, source: SourceParc},
	}
	for _, c := range cas {
		a := Resoudre(c.c)
		if a.Definie != c.def || a.Source != c.source || a.Groupe != c.groupe ||
			(c.def && a.Version.String() != c.v) {
			t.Errorf("%s : %+v", c.nom, a)
		}
	}
}

func TestResoudreSignaleLIllisible(t *testing.T) {
	if a := Resoudre(Cibles{Derogation: "2.2"}); a.Illisible != "2.2" {
		t.Errorf("dérogation illisible non rendue : %+v", a)
	}
	if a := Resoudre(Cibles{Groupes: map[string]string{"g": "abc"}}); a.Illisible != "abc" {
		t.Errorf("cible de groupe illisible non rendue : %+v", a)
	}
}

func TestSituer(t *testing.T) {
	cible := Attendue{Definie: true, Version: V(2, 3, 1), Source: SourceParc}
	cas := map[string]Etat{
		"2.3.1+g1939a3b (2026-08-14)": EtatAJour,
		"2.3.0":                       EtatEnRetard,
		"2.2.9 (build local)":         EtatEnRetard,
		"2.4.0":                       EtatEnAvance,
		"":                            EtatInconnue,
		"dev":                         EtatInconnue,
	}
	for declaree, attendu := range cas {
		if got := Situer(declaree, cible); got != attendu {
			t.Errorf("Situer(%q) = %q, attendu %q", declaree, got, attendu)
		}
	}
	// Sans cible, même une version illisible n'est pas « inconnue » : rien
	// ne sera fait, il n'y a rien à regarder.
	if got := Situer("", Attendue{}); got != EtatSansCible {
		t.Errorf("sans cible : %q", got)
	}
}

func TestAUnEcart(t *testing.T) {
	for _, e := range OrdreDesEtats {
		attendu := e == EtatEnRetard || e == EtatInconnue
		if e.AUnEcart() != attendu {
			t.Errorf("%q.AUnEcart() = %v", e, !attendu)
		}
	}
}
