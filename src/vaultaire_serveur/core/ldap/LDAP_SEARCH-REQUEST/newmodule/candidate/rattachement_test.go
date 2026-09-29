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

// POINT 123 : une entrée ne déclare plus ce qu'elle ne sert pas.
//
// `posixAccount` et `posixGroup` étaient annoncés alors qu'aucun attribut POSIX
// n'était servi — ni uidNumber, ni gidNumber, ni homeDirectory, ni loginShell,
// ni memberUid. Un client RFC 2307 trouvait l'entrée puis échouait à construire
// le compte : l'erreur apparaissait loin de sa cause.
//
// Ce test vérifie les deux moitiés de la règle : la classe est partie, ET aucun
// attribut POSIX n'est apparu entre-temps. Si l'un des deux change, il faut que
// l'autre change aussi — c'est le fond du point.
func TestAucuneEntreeNAnnoncePosixSansLeServir(t *testing.T) {
	attributsPosix := []string{
		"uidnumber", "gidnumber", "homedirectory", "loginshell", "gecos", "memberuid",
	}

	u := UserEntry{BaseDN: "enov.local", Rattachements: []string{"enov.local"}}
	g := GroupEntry{Name: "admins", BaseDN: "enov.local"}

	for _, cas := range []struct {
		nom    string
		entrée ldapinterface.LDAPEntry
		classe string
	}{
		{"compte", u, "posixaccount"},
		{"groupe", g, "posixgroup"},
	} {
		sert := false
		for _, a := range attributsPosix {
			if len(cas.entrée.GetAttribute(a)) > 0 {
				sert = true
				break
			}
		}

		annonce := false
		for _, c := range cas.entrée.ObjectClasses() {
			if strings.EqualFold(c, cas.classe) {
				annonce = true
				break
			}
		}

		if annonce && !sert {
			t.Errorf("%s : annonce %q sans servir un seul attribut POSIX — "+
				"un client RFC 2307 trouvera l'entrée et ne pourra rien en faire",
				cas.nom, cas.classe)
		}
		if sert && !annonce {
			t.Errorf("%s : sert des attributs POSIX sans annoncer %q — "+
				"aucun client RFC 2307 ne le trouvera", cas.nom, cas.classe)
		}
	}
}

// Les classes sur lesquelles les clients du parc filtrent RESTENT, elles.
//
// C'est la moitié rassurante du point 123 : retirer les classes POSIX ne devait
// toucher que sssd, nslcd et les NAS en mode Unix. Keycloak cherche `person`,
// `inetOrgPerson`, `user` et `groupOfNames` ; Nextcloud cherche `group`.
func TestLesClassesDontLesClientsDependentRestent(t *testing.T) {
	u := UserEntry{BaseDN: "enov.local", Rattachements: []string{"enov.local"}}
	for _, attendue := range []string{"inetOrgPerson", "organizationalPerson", "person", "user"} {
		if !contient(u.ObjectClasses(), attendue) {
			t.Errorf("un compte n'annonce plus %q : Keycloak et Nextcloud ne le "+
				"trouveront plus", attendue)
		}
	}

	g := GroupEntry{Name: "admins", BaseDN: "enov.local"}
	for _, attendue := range []string{"top", "groupOfNames", "group"} {
		if !contient(g.ObjectClasses(), attendue) {
			t.Errorf("un groupe n'annonce plus %q", attendue)
		}
	}
}

// Et le sous-schéma ne déclare plus posixAccount — il le faisait sous un OID qui
// n'est pas le sien (RFC 2307 : 1.3.6.1.1.1.2.0).
func TestLeSousSchemaNeDeclarePlusPosix(t *testing.T) {
	for _, def := range NewSchemaEntry().ObjectClassDefs {
		if strings.Contains(strings.ToLower(def), "posix") {
			t.Errorf("le sous-schéma déclare encore une classe POSIX : %s", def)
		}
	}
}

func contient(liste []string, valeur string) bool {
	for _, v := range liste {
		if strings.EqualFold(v, valeur) {
			return true
		}
	}
	return false
}
