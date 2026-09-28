package candidate

import (
	"strings"
	"testing"

	ldapinterface "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate/ldap_interface"
)

// Point 120 : ce à quoi une entrée est rattachée décide de qui a le droit de la
// lire. Ce fichier éprouve les rattachements eux-mêmes ; la règle qui les
// interprète est éprouvée dans newmodule/security.

// LE piège du point, et la première version du correctif s'y est prise.
//
// `BaseDN` compose le DN ; sur le chemin d'une recherche `one` ou `sub`, c'est le
// domaine que le CLIENT a demandé, pas celui où vit le compte. S'en servir comme
// valeur de secours pour les droits autoriserait tout compte par construction :
// le filtre ne verrait jamais que le domaine qui vient d'être autorisé.
func TestUnCompteNeSeRattachePasAuDomaineDeSonDN(t *testing.T) {
	// Un compte de admin.enov.local, rendu dans une recherche sur enov.local.
	u := UserEntry{BaseDN: "enov.local", Rattachements: []string{"admin.enov.local"}}

	domaines := u.Domaines()
	if len(domaines) != 1 || domaines[0] != "admin.enov.local" {
		t.Fatalf("Domaines() = %v : c'est le rattachement réel du compte qui décide "+
			"des droits, pas le domaine demandé", domaines)
	}

	// Et sans rattachement, RIEN — surtout pas BaseDN.
	sans := UserEntry{BaseDN: "enov.local"}
	if d := sans.Domaines(); len(d) != 0 {
		t.Errorf("Domaines() = %v pour un compte sans rattachement : le secours sur "+
			"BaseDN autoriserait tout compte, puisque BaseDN est le domaine demandé", d)
	}
}

// LE DN NE DISTINGUE PAS un compte de sous-domaine.
//
// C'est ce qui rend le rattachement indispensable, et c'est contre-intuitif :
// `ToRootDN` ne garde que les deux derniers labels. Si ce test venait à échouer
// parce que les DN portent enfin le sous-domaine, il resterait juste d'écarter
// sur le rattachement — mais l'inverse, déduire le domaine du DN, serait alors
// tentant et toujours faux pour les autres formes.
func TestDeuxComptesDeDomainesDifferentsOntLeMemeDN(t *testing.T) {
	a := UserEntry{BaseDN: "enov.local", Rattachements: []string{"enov.local"}}
	a.User.Username = "alice"
	b := UserEntry{BaseDN: "admin.enov.local", Rattachements: []string{"admin.enov.local"}}
	b.User.Username = "alice"

	if a.DN() != b.DN() {
		// Un ÉCHEC, pas un saut : si les DN se mettent à porter le sous-domaine,
		// c'est une bonne nouvelle, mais tout le raisonnement du point 120 — et ce
		// qu'on peut ou non déduire d'un DN — est à relire. Passer en silence
		// laisserait ce test endormi pour toujours.
		t.Errorf("les DN diffèrent désormais (%q vs %q) : ToRootDN a changé, "+
			"relire le raisonnement du point 120", a.DN(), b.DN())
		return
	}
	if !strings.Contains(a.DN(), "dc=enov,dc=local") {
		t.Errorf("DN inattendu : %q", a.DN())
	}
}

// Les autres types d'entrée se rattachent bien à leur propre domaine.
func TestChaqueTypeDEntreeDitSonRattachement(t *testing.T) {
	cas := []struct {
		nom     string
		entrée  ldapinterface.LDAPEntry
		attendu []string
	}{
		{"groupe", GroupEntry{Name: "admins", BaseDN: "admin.enov.local"},
			[]string{"admin.enov.local"}},
		{"unité d'organisation", OUEntry{Name: "users", BaseDN: "admin.enov.local"},
			[]string{"admin.enov.local"}},
		{"domaine, forme pointée", DomainEntry{DNName: "admin.enov.local"},
			[]string{"admin.enov.local"}},
		{"domaine, forme DN", DomainEntry{DNName: "dc=admin,dc=enov,dc=local"},
			[]string{"admin.enov.local"}},
		{"compte", UserEntry{BaseDN: "enov.local", Rattachements: []string{"a.local", "b.local"}},
			[]string{"a.local", "b.local"}},
	}

	for _, c := range cas {
		obtenu := c.entrée.Domaines()
		if len(obtenu) != len(c.attendu) {
			t.Errorf("%s : Domaines() = %v, attendu %v", c.nom, obtenu, c.attendu)
			continue
		}
		for i := range obtenu {
			if obtenu[i] != c.attendu[i] {
				t.Errorf("%s : Domaines() = %v, attendu %v", c.nom, obtenu, c.attendu)
				break
			}
		}
	}
}

// LE ROOTDSE ET LE SOUS-SCHÉMA ne se rattachent à rien, et c'est voulu.
//
// Ils sont servis par le chemin qui court-circuite le filtre, parce qu'ils
// doivent rester lisibles sans authentification (RFC 4512). S'ils passaient un
// jour par le filtre, ils seraient écartés — c'est le bon sens du refus : une
// liste vide ferme, elle n'ouvre pas.
func TestLeRootDSEEtLeSchemaNeSeRattachentARien(t *testing.T) {
	if d := NewRootDSE().Domaines(); len(d) != 0 {
		t.Errorf("RootDSE rattaché à %v", d)
	}
	if d := NewSchemaEntry().Domaines(); len(d) != 0 {
		t.Errorf("sous-schéma rattaché à %v", d)
	}
}

// Un BaseDN vide ne devient pas un rattachement vide qui aurait l'air renseigné.
//
// « [""] » et « [] » ne se distinguent pas à la lecture d'un journal, mais la
// première forme ferait boucler le filtre sur une chaîne vide. Les deux sont
// refusées ; autant n'en produire qu'une.
func TestUnDomaineVideNeDevientPasUnRattachement(t *testing.T) {
	for nom, e := range map[string]ldapinterface.LDAPEntry{
		"groupe":  GroupEntry{Name: "x"},
		"OU":      OUEntry{Name: "users"},
		"domaine": DomainEntry{},
	} {
		if d := e.Domaines(); len(d) != 0 {
			t.Errorf("%s sans domaine : Domaines() = %#v, attendu vide", nom, d)
		}
	}
}
