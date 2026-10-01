package newmodule

import (
	"errors"
	"strings"
	"testing"

	candidate "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate"
	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
)

func entree(user, domaine string) candidate.UserEntry {
	return candidate.UserEntry{User: ldapstorage.User{Username: user}, BaseDN: domaine}
}

func injecter(t *testing.T, accordees map[string]bool, lecteurs map[string]bool, errGroupes error) {
	t.Helper()
	g, a, p := groupesDe, aLAction, peutLireEn
	t.Cleanup(func() { groupesDe, aLAction, peutLireEn = g, a, p })
	groupesDe = func(string) ([]int, error) { return []int{1}, errGroupes }
	aLAction = func(_ []int, k string) bool { return accordees[k] }
	peutLireEn = func(l, d string) bool { return lecteurs[l+"@"+d] }
}

func TestDroitsServiceDemandes(t *testing.T) {
	cas := map[string]bool{
		"":                           false,
		"*":                          false, // « * » désigne les attributs utilisateur
		"uid,memberOf":               false,
		"+":                          false, // trop coûteux sur un sous-arbre
		"uid,vaultaireServiceRights": true,
		"VAULTAIRESERVICERIGHTS":     true,
		"1.1":                        false,
	}
	for attrs, attendu := range cas {
		var l []string
		if attrs != "" {
			l = strings.Split(attrs, ",")
		}
		if got := droitsServiceDemandes(l); got != attendu {
			t.Errorf("%q : %t, attendu %t", attrs, got, attendu)
		}
	}
}

func TestDroitsServiceFiltresEtLimitesAuCompte(t *testing.T) {
	injecter(t,
		map[string]bool{"read:nexus": true, "write:nexus_admin": true, "write:user": true},
		map[string]bool{"svc@acme.lan": true}, nil)

	// Le compte lui-même : ses clés de service, et elles seules.
	got := strings.Join(droitsService("alice", entree("alice", "acme.lan")), ",")
	if got != "read:nexus,write:nexus_admin" {
		t.Errorf("propre entrée : %q", got)
	}
	// Casse indifférente.
	if len(droitsService("ALICE", entree("alice", "acme.lan"))) != 2 {
		t.Error("comparaison sensible à la casse")
	}
	// Un compte de service qui peut lire les comptes du domaine.
	if len(droitsService("svc", entree("alice", "acme.lan"))) != 2 {
		t.Error("lecteur autorisé refusé")
	}
	// Le même, sur un autre domaine : rien.
	if r := droitsService("svc", entree("alice", "rh.acme.lan")); r != nil {
		t.Errorf("lecteur hors de son domaine : %v", r)
	}
	// Un tiers quelconque : rien.
	if r := droitsService("bob", entree("alice", "acme.lan")); r != nil {
		t.Errorf("tiers : %v", r)
	}
	// Session anonyme : rien.
	if r := droitsService("", entree("alice", "acme.lan")); r != nil {
		t.Errorf("anonyme : %v", r)
	}
}

func TestDroitsServiceGroupesIllisibles(t *testing.T) {
	injecter(t, map[string]bool{"read:nexus": true}, nil, errors.New("révoqué"))
	if r := droitsService("alice", entree("alice", "acme.lan")); r != nil {
		t.Errorf("compte révoqué ou illisible : %v", r)
	}
}

func TestAttributAbsentSansValeurEtOperationnel(t *testing.T) {
	e := entree("alice", "acme.lan")
	if _, ok := e.GetAttributes([]string{"+"}, false)[candidate.AttrServiceRights]; ok {
		t.Error("attribut sans valeur émis")
	}
	e.ServiceRights = []string{"read:nexus"}
	if _, ok := e.GetAttributes([]string{"*"}, false)[candidate.AttrServiceRights]; ok {
		t.Error("attribut opérationnel émis sur « * »")
	}
	v := e.GetAttributes([]string{"vaultaireServiceRights"}, false)[candidate.AttrServiceRights]
	if len(v) != 1 || v[0] != "read:nexus" {
		t.Errorf("valeurs : %v", v)
	}
}

func TestClesDeServiceContientNexus(t *testing.T) {
	got := strings.Join(clesDeService(), ",")
	if got != "read:nexus,write:nexus,write:nexus_admin" {
		t.Errorf("clesDeService = %q", got)
	}
}
