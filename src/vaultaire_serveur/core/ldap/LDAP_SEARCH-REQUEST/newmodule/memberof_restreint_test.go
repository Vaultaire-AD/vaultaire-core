package newmodule

import (
	"testing"

	"vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate"
	ldapinterface "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate/ldap_interface"
	"vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/security"
	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
)

// TO-DO 132, sur l'ENCHAÎNEMENT du gestionnaire : droits, puis filtre.
//
// Retirer de `memberOf` le nom des groupes illisibles ne suffit pas si le
// filtre de la recherche s'évalue AVANT. `(memberOf=cn=secrets,…)` rendrait
// alors le compte ou ne le rendrait pas selon qu'il est membre du groupe caché :
// la fuite serait devenue un oracle, et les groupes d'un sous-domaine
// resteraient énumérables — nom par nom, et membre par membre.
//
// Le gestionnaire applique donc `Filtrer` (droits) puis `candidate.Filtre`
// (filtre LDAP), dans cet ordre. Ce test rejoue les deux, tels quels.

const (
	groupeLisible = "cn=ventes,ou=groups,dc=enov,dc=local"
	groupeCache   = "cn=secrets,ou=groups,dc=enov,dc=local" // vit dans admin.enov.local
)

func compteDansLesDeux() []ldapinterface.LDAPEntry {
	u := candidate.UserEntry{BaseDN: "enov.local",
		Rattachements: []string{"enov.local", "admin.enov.local"},
		Groups: []candidate.Appartenance{
			{DN: groupeLisible, Domaine: "enov.local"},
			{DN: groupeCache, Domaine: "admin.enov.local"},
		}}
	u.User.Username = "alice"
	return []ldapinterface.LDAPEntry{u}
}

func rechercheParGroupe(portee *security.PorteeDeRecherche, groupe string) []ldapinterface.LDAPEntry {
	retenues, _ := portee.Filtrer(compteDansLesDeux())
	filtre := &ldapstorage.LDAPFilter{Type: ldapstorage.FilterEquality, Attribute: "memberOf", Value: groupe}
	return candidate.Filtre(retenues, filtre, "enov.local", 2)
}

func TestUnFiltreSurMemberOfNeSondePasUnGroupeCache(t *testing.T) {
	// Délégué de enov.local, SANS propagation.
	delegue := security.NouvellePortee([]string{"(0:enov.local)"})

	if n := len(rechercheParGroupe(delegue, groupeCache)); n != 0 {
		t.Fatalf("(memberOf=%s) rend %d entrée(s) à un compte qui n'a pas le droit de lire "+
			"ce groupe : le filtre répond à une question sur ce qu'il ne peut pas voir", groupeCache, n)
	}
	// Le groupe qu'il PEUT lire reste cherchable : la restriction ne casse pas
	// la recherche par appartenance, que Keycloak et Nextcloud emploient.
	if n := len(rechercheParGroupe(delegue, groupeLisible)); n != 1 {
		t.Fatalf("(memberOf=%s) rend %d entrée(s), attendu 1", groupeLisible, n)
	}
}

func TestAvecPropagationLeFiltreSurMemberOfTrouveLesDeux(t *testing.T) {
	admin := security.NouvellePortee([]string{"(1:enov.local)"})

	for _, groupe := range []string{groupeLisible, groupeCache} {
		if n := len(rechercheParGroupe(admin, groupe)); n != 1 {
			t.Errorf("(memberOf=%s) rend %d entrée(s) à un compte qui a la propagation, attendu 1", groupe, n)
		}
	}
}
