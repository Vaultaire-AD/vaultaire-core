package domainname

import (
	"reflect"
	"testing"
)

func TestAncetres(t *testing.T) {
	cas := map[string][]string{
		"infra.cloud.acme.lan": {"acme.lan", "cloud.acme.lan"},
		"infra.acme.lan":       {"acme.lan"},
		"acme.lan":             nil,
		"Infra.ACME.lan.":      {"acme.lan"},
	}
	for d, attendu := range cas {
		if got := Ancetres(d); !reflect.DeepEqual(got, attendu) {
			t.Errorf("Ancetres(%q) = %v, attendu %v", d, got, attendu)
		}
	}
}

func TestDomainePrincipal(t *testing.T) {
	cas := map[string]string{
		"infra.cloud.test.fr": "test.fr",
		"test.fr":             "test.fr",
		"RH.Acme.Lan.":        "acme.lan",
	}
	for d, attendu := range cas {
		got, err := DomainePrincipal(d)
		if err != nil || got != attendu {
			t.Errorf("DomainePrincipal(%q) = %q, %v ; attendu %q", d, got, err, attendu)
		}
	}
	if _, err := DomainePrincipal("lan"); err == nil {
		t.Error("un seul label doit être refusé")
	}
}

func TestValiderDomaine(t *testing.T) {
	for _, ok := range []string{"acme.lan", "infra.cloud.acme.lan", "a-b.c1.fr", "ACME.lan"} {
		if err := ValiderDomaine(ok); err != nil {
			t.Errorf("%q refusé : %v", ok, err)
		}
	}
	for _, ko := range []string{"", "lan", "acme..lan", "-a.lan", "a_b.lan", "a b.lan", "acme.lan/x"} {
		if err := ValiderDomaine(ko); err == nil {
			t.Errorf("%q accepté", ko)
		}
	}
}

func TestDomainesPrincipauxSansDoublon(t *testing.T) {
	got := DomainesPrincipaux([]string{"infra.test.fr", "rh.test.fr", "acme.lan", "x"})
	if !reflect.DeepEqual(got, []string{"test.fr", "acme.lan"}) {
		t.Errorf("got %v", got)
	}
}

func TestSousDomaineDe(t *testing.T) {
	if !SousDomaineDe("infra.test.fr", "test.fr") || !SousDomaineDe("test.fr", "TEST.fr") {
		t.Error("sous-domaine non reconnu")
	}
	if SousDomaineDe("attest.fr", "test.fr") {
		t.Error("attest.fr n'est pas sous test.fr")
	}
}
