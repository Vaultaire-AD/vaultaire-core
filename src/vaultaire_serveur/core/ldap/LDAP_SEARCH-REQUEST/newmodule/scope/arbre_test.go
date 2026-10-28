package scope

import (
	"sort"
	"strings"
	"testing"

	"vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate"
	ldapinterface "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate/ldap_interface"
)

// TO-DO 245 — la portée suit l'arbre des DN.

func TestNatureDeLaBase(t *testing.T) {
	cas := map[string]natureDeBase{
		"dc=acme,dc=lan":                          baseDomaine,
		"DC=Infra, DC=acme,DC=lan":                baseDomaine,
		"ou=users,dc=acme,dc=lan":                 baseOU,
		"OU=Groups,dc=acme,dc=lan":                baseOU,
		"uid=alice,ou=users,dc=acme,dc=lan":       baseFeuille,
		"cn=Infra,ou=groups,dc=acme,dc=lan":       baseFeuille,
	}
	for base, attendu := range cas {
		if obtenu := natureDe(base); obtenu != attendu {
			t.Errorf("natureDe(%q) = %d, attendu %d", base, obtenu, attendu)
		}
	}
}

func TestDansLaPorteeSelonLaRFC(t *testing.T) {
	base := normaliserDN("ou=users, DC=acme,dc=lan")
	cas := []struct {
		dn    string
		scope int
		dans  bool
	}{
		{"ou=users,dc=acme,dc=lan", 0, true},
		{"uid=a,ou=users,dc=acme,dc=lan", 0, false},
		{"uid=a,ou=users,dc=acme,dc=lan", 1, true},
		{"ou=users,dc=acme,dc=lan", 1, false}, // la base n'est pas son propre enfant
		{"ou=groups,dc=acme,dc=lan", 1, false},
		{"x=1,uid=a,ou=users,dc=acme,dc=lan", 1, false},
		{"x=1,uid=a,ou=users,dc=acme,dc=lan", 2, true},
		{"ou=users,dc=acme,dc=lan", 2, true},
		{"cn=g,ou=groups,dc=acme,dc=lan", 2, false},
		{"uid=a,xou=users,dc=acme,dc=lan", 2, false}, // un suffixe de chaîne n'est pas un ancêtre
	}
	for _, c := range cas {
		if obtenu := dansLaPortee(normaliserDN(c.dn), base, c.scope); obtenu != c.dans {
			t.Errorf("dansLaPortee(%q, scope=%d) = %v, attendu %v", c.dn, c.scope, obtenu, c.dans)
		}
	}
}

func TestSousDomainesIntermediairesCompris(t *testing.T) {
	servis := []string{"acme.lan", "Infra.acme.lan", "svc.acme.lan", "web.dev.acme.lan", "autre.lan"}

	directs := sousDomaines(servis, "acme.lan", true)
	if strings.Join(directs, " ") != "dev.acme.lan infra.acme.lan svc.acme.lan" {
		t.Errorf("enfants directs de acme.lan = %v", directs)
	}
	tous := sousDomaines(servis, "acme.lan", false)
	if strings.Join(tous, " ") != "dev.acme.lan infra.acme.lan svc.acme.lan web.dev.acme.lan" {
		t.Errorf("descendants de acme.lan = %v", tous)
	}
	if d := sousDomaines(servis, "svc.acme.lan", true); len(d) != 0 {
		t.Errorf("svc.acme.lan n'a pas d'enfant, rendu %v", d)
	}
	if d := sousDomaines(servis, "dev.acme.lan", true); strings.Join(d, " ") != "web.dev.acme.lan" {
		t.Errorf("enfants de dev.acme.lan = %v", d)
	}
}

// L'annuaire du constat, tel que le résolveur le fabrique : DN aplatis.
func annuaireAplati() []ldapinterface.LDAPEntry {
	servis := []string{"acme.lan", "infra.acme.lan", "svc.acme.lan"}
	alice := candidate.UserEntry{BaseDN: "acme.lan", Rattachements: []string{"infra.acme.lan"}}
	alice.User.Username = "alice.martin"
	svc := candidate.UserEntry{BaseDN: "acme.lan", Rattachements: []string{"svc.acme.lan"}}
	svc.User.Username = "svc_keycloak"
	entrees := append(ousDuDomaine("acme.lan"),
		alice, svc,
		candidate.GroupEntry{Name: "Infra", BaseDN: "infra.acme.lan"},
		candidate.GroupEntry{Name: "Services", BaseDN: "svc.acme.lan"},
	)
	return append(entrees, entreesDeDomaines(servis, []string{"acme.lan", "infra.acme.lan", "svc.acme.lan"})...)
}

func dns(entrees []ldapinterface.LDAPEntry) string {
	var l []string
	for _, e := range entrees {
		l = append(l, e.DN())
	}
	sort.Strings(l)
	return strings.Join(l, " | ")
}

// Les recherches du constat, une par une.
func TestLArbreDuConstat(t *testing.T) {
	tout := annuaireAplati()
	cas := []struct {
		base    string
		scope   int
		attendu string
	}{
		{"ou=users,dc=acme,dc=lan", 1, "uid=alice.martin,ou=users,dc=acme,dc=lan | uid=svc_keycloak,ou=users,dc=acme,dc=lan"},
		{"ou=groups,dc=acme,dc=lan", 1, "cn=Infra,ou=groups,dc=acme,dc=lan | cn=Services,ou=groups,dc=acme,dc=lan"},
		{"uid=alice.martin,ou=users,dc=acme,dc=lan", 1, ""},
		{"ou=users,dc=acme,dc=lan", 2, "ou=users,dc=acme,dc=lan | uid=alice.martin,ou=users,dc=acme,dc=lan | uid=svc_keycloak,ou=users,dc=acme,dc=lan"},
		{"dc=acme,dc=lan", 1, "dc=infra,dc=acme,dc=lan | dc=svc,dc=acme,dc=lan | ou=groups,dc=acme,dc=lan | ou=users,dc=acme,dc=lan"},
		{"dc=svc,dc=acme,dc=lan", 1, ""},
	}
	for _, c := range cas {
		if obtenu := dns(DansLaPortee(tout, c.base, c.scope)); obtenu != c.attendu {
			t.Errorf("scope=%d sous %s :\n  rendu   %s\n  attendu %s", c.scope, c.base, obtenu, c.attendu)
		}
	}
}

// LA SENTINELLE : quelle que soit la base et la portée, aucune entrée rendue
// n'est hors de la portée.
func TestAucuneEntreeHorsDeLaPortee(t *testing.T) {
	tout := annuaireAplati()
	for _, base := range tout {
		for _, scope := range []int{0, 1, 2} {
			b := normaliserDN(base.DN())
			for _, e := range DansLaPortee(tout, base.DN(), scope) {
				if !dansLaPortee(normaliserDN(e.DN()), b, scope) {
					t.Errorf("scope=%d sous %s : %s rendue hors de la portée", scope, base.DN(), e.DN())
				}
				if scope == 1 && normaliserDN(e.DN()) == b {
					t.Errorf("scope=1 sous %s : la base rendue comme son propre enfant", base.DN())
				}
			}
		}
	}
}

// hasSubordinates dit la vérité de l'arbre.
func TestHasSubordinatesSuitLArbre(t *testing.T) {
	servis := []string{"acme.lan", "infra.acme.lan", "web.dev.acme.lan"}
	for _, e := range entreesDeDomaines(servis, []string{"acme.lan", "infra.acme.lan", "dev.acme.lan", "web.dev.acme.lan"}) {
		attendu := map[string]string{
			"dc=acme,dc=lan":             "TRUE",  // la racine porte les OU
			"dc=infra,dc=acme,dc=lan":    "FALSE", // ni OU ni sous-domaine
			"dc=dev,dc=acme,dc=lan":      "TRUE",  // web.dev
			"dc=web,dc=dev,dc=acme,dc=lan": "FALSE",
		}[e.DN()]
		if v := e.GetAttribute("hasSubordinates"); len(v) != 1 || v[0] != attendu {
			t.Errorf("%s : hasSubordinates = %v, attendu %s", e.DN(), v, attendu)
		}
	}
}
