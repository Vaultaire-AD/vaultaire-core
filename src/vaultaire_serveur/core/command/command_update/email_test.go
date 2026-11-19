package commandupdate

import "testing"

func TestParamsChangementEmail(t *testing.T) {
	// La console colle à « --email » ce qui le suit : un seul argument.
	p, ok, err := ParamsChangementEmail([]string{"-u", "lea", "--email", "lea@acme.fr"})
	if !ok || err != nil || p["username"] != "lea" || p["email"] != "lea@acme.fr" {
		t.Fatalf("forme simple : %v %v %v", p, ok, err)
	}
	if p, ok, err := ParamsChangementEmail([]string{"-u", "lea", "--email auto"}); !ok || err != nil || p["email"] != "auto" {
		t.Fatalf("forme collée : %v %v %v", p, ok, err)
	}
	if _, ok, _ := ParamsChangementEmail([]string{"-u", "lea", "-p", "Un mot de passe"}); ok {
		t.Fatal("un changement de mot de passe pris pour un changement d'adresse")
	}
	for _, mauvais := range [][]string{
		{"-u", "lea", "--email"},
		{"-u", "lea", "--email", "a@b.fr", "c@d.fr"},
	} {
		if _, ok, err := ParamsChangementEmail(mauvais); !ok || err == nil {
			t.Errorf("%v : refus attendu", mauvais)
		}
	}
}
