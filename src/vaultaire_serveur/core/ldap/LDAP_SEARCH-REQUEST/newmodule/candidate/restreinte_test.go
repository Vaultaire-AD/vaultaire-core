package candidate

import (
	"reflect"
	"testing"

	ldapinterface "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate/ldap_interface"
)

// TO-DO 132 : `memberOf` nommait les groupes des sous-domaines qu'un délégué
// sans propagation n'a pas le droit de lire.
//
// La règle : un attribut ne nomme que ce que l'appelant pourrait lire comme
// entrée. Ce fichier éprouve ce que l'ENTRÉE fait de cette règle ; le fait que
// le contrôle d'accès l'applique à chaque recherche est éprouvé dans
// newmodule/security.

const (
	dnParent = "cn=ventes,ou=groups,dc=enov,dc=local"
	dnEnfant = "cn=secrets,ou=groups,dc=enov,dc=local" // vit dans admin.enov.local
)

// alice est membre d'un groupe du domaine et d'un groupe du sous-domaine.
//
// Noter les deux DN : ils portent le MÊME suffixe. `ToRootDN` ne garde que les
// deux derniers labels, donc rien dans le DN ne dit que le second groupe vient
// d'ailleurs — c'est pour cela que le domaine voyage avec lui.
func alice() UserEntry {
	u := UserEntry{BaseDN: "enov.local", Rattachements: []string{"enov.local", "admin.enov.local"},
		Groups: []Appartenance{
			{DN: dnParent, Domaine: "enov.local"},
			{DN: dnEnfant, Domaine: "admin.enov.local"},
		}}
	u.User.Username = "alice"
	return u
}

// seul rend un contrôle d'accès qui n'autorise qu'un domaine — un délégué SANS
// propagation.
func seul(domaine string) func(string) bool {
	return func(d string) bool { return d == domaine }
}

// LE test du point : le groupe du sous-domaine ne figure plus dans memberOf.
func TestMemberOfNeNommePasUnGroupeIllisible(t *testing.T) {
	vue := alice().Restreinte(seul("enov.local"))

	if got := vue.GetAttribute("memberOf"); !reflect.DeepEqual(got, []string{dnParent}) {
		t.Fatalf("memberOf = %v, attendu le seul %s : le nom d'un groupe d'un "+
			"sous-domaine sort encore, et ces groupes restent énumérables", got, dnParent)
	}
}

// Et dans l'autre sens : un délégué du SOUS-domaine ne lit pas le nom des
// groupes du domaine parent. C'était le cas sur une recherche `base`, qui
// rendait tous les groupes du compte, d'où qu'ils viennent.
func TestMemberOfNeNommePasNonPlusLesGroupesDuParent(t *testing.T) {
	vue := alice().Restreinte(seul("admin.enov.local"))

	if got := vue.GetAttribute("memberOf"); !reflect.DeepEqual(got, []string{dnEnfant}) {
		t.Fatalf("memberOf = %v, attendu le seul %s", got, dnEnfant)
	}
}

// Qui a le droit de tout lire lit tout : la restriction ne doit rien retirer à
// un compte autorisé, sans quoi Keycloak perdrait des appartenances.
func TestQuiPeutToutLireGardeToutMemberOf(t *testing.T) {
	vue := alice().Restreinte(func(string) bool { return true })

	if got := vue.GetAttribute("memberOf"); !reflect.DeepEqual(got, []string{dnParent, dnEnfant}) {
		t.Fatalf("memberOf = %v : une appartenance a été retirée à un compte qui a tous les droits", got)
	}
}

// L'entrée reçue n'est PAS modifiée. Elle peut être partagée — la même liste
// sert à toutes les copies — et une restriction faite sur place pour un compte
// amputerait la réponse du suivant.
func TestRestreindreNeModifiePasLOriginal(t *testing.T) {
	u := alice()
	_ = u.Restreinte(seul("enov.local"))

	if len(u.Groups) != 2 || u.Groups[1].DN != dnEnfant {
		t.Fatalf("l'entrée d'origine a été modifiée : %v", u.Groups)
	}
	if got := u.GetAttribute("memberOf"); len(got) != 2 {
		t.Errorf("memberOf de l'original = %v", got)
	}
}

// Une appartenance SANS domaine est écartée, même pour qui lit tout : l'oubli
// de renseigner le domaine rend le groupe invisible, il ne le diffuse pas.
func TestUneAppartenanceSansDomaineEstEcartee(t *testing.T) {
	u := UserEntry{BaseDN: "enov.local", Rattachements: []string{"enov.local"},
		Groups: []Appartenance{{DN: dnParent}}}

	vue := u.Restreinte(func(string) bool { return true })

	if got := vue.GetAttribute("memberOf"); len(got) != 0 {
		t.Fatalf("memberOf = %v : un groupe dont on ne sait pas d'où il vient a été rendu", got)
	}
}

// Sans aucun groupe lisible, l'attribut est ABSENT — pas présent et vide. Un
// attribut sans valeur n'existe pas en LDAP (RFC 4512 §2.5), et un client
// strict rejette l'entrée qui en porte un.
func TestSansGroupeLisibleMemberOfEstAbsent(t *testing.T) {
	vue := alice().Restreinte(seul("autre.local"))

	if v, présent := vue.GetAttributes([]string{"*"}, false)["memberof"]; présent {
		t.Fatalf("memberOf présent avec %d valeur(s) alors qu'aucun groupe n'est lisible", len(v))
	}
	if v := vue.GetAttribute("memberOf"); v != nil {
		t.Errorf("memberOf demandé nommément = %v, attendu rien", v)
	}
}

// Le reste de l'entrée ne bouge pas : seuls les attributs qui NOMMENT autre
// chose sont concernés.
func TestLaRestrictionNeToucheQueCeQuiNommeAutreChose(t *testing.T) {
	u := alice()
	u.User.Email = "alice@enov.local"
	vue := u.Restreinte(seul("enov.local")).(UserEntry)

	if vue.DN() != u.DN() || vue.User.Email != u.User.Email ||
		!reflect.DeepEqual(vue.Domaines(), u.Domaines()) {
		t.Fatalf("l'entrée restreinte diffère de l'original au-delà de memberOf : %+v", vue)
	}
}

// Les entrées qui ne nomment qu'elles-mêmes se rendent telles quelles — y
// compris le groupe, dont `member` est lisible par construction (voir
// GroupEntry.Restreinte).
func TestLesAutresEntreesSeRendentTellesQuelles(t *testing.T) {
	aucun := func(string) bool { return false }
	groupe := GroupEntry{Name: "ventes", BaseDN: "enov.local",
		Members: []string{"uid=alice,ou=users,dc=enov,dc=local"}}

	for nom, e := range map[string]ldapinterface.LDAPEntry{
		"groupe":      groupe,
		"unité":       OUEntry{Name: "users", BaseDN: "enov.local"},
		"domaine":     DomainEntry{DNName: "enov.local"},
		"racine":      RootDSEEntry{VendorName: "Vaultaire"},
		"sous-schéma": SchemaEntry{CN: "schema"},
	} {
		if got := e.Restreinte(aucun); !reflect.DeepEqual(got, e) {
			t.Errorf("%s : l'entrée restreinte diffère de l'original", nom)
		}
	}
	if got := groupe.Restreinte(aucun).GetAttribute("member"); len(got) != 1 {
		t.Errorf("member = %v", got)
	}
}
