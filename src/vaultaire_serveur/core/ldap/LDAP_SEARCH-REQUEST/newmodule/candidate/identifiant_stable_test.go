package candidate

import (
	"sort"
	"testing"

	"vaultaire/core/identifiant"
	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
)

// L'identifiant stable d'une entrée — point 129.

const uuidDAlice = "597ae2f6-16a6-4027-98f4-d28b5365dc14"

func compteIdentifie(nom, uuid string) UserEntry {
	return UserEntry{
		User: ldapstorage.User{Username: nom, Firstname: "Alice", Lastname: "Martin",
			Email: "alice@enov.local", EntryUUID: uuid},
		BaseDN: "enov.local", Rattachements: []string{"enov.local"},
	}
}

// LE test du point. `entryUUID` valait le nom du compte : il changeait donc
// exactement quand on avait besoin qu'il ne change pas. Keycloak, qui reconnaît
// un compte importé par cet attribut, créait un second compte au renommage.
func TestLIdentifiantSurvitAuRenommage(t *testing.T) {
	avant := compteIdentifie("alice", uuidDAlice)
	apres := compteIdentifie("alice.martin", uuidDAlice) // même ligne, renommée

	for _, attr := range attributsIdentifiant {
		a, b := avant.GetAttribute(attr), apres.GetAttribute(attr)
		if len(a) != 1 || len(b) != 1 {
			t.Fatalf("%s : %v avant, %v après — une valeur attendue de chaque côté", attr, a, b)
		}
		if a[0] != b[0] {
			t.Errorf("%s vaut %q avant le renommage et %q après : un client qui s'y fie "+
				"verrait un compte NEUF et en créerait un second", attr, a[0], b[0])
		}
		if a[0] == "alice" || a[0] == "vaultaire-alice" {
			t.Errorf("%s vaut %q : c'est encore le nom du compte, pas un identifiant", attr, a[0])
		}
	}
	if avant.DN() == apres.DN() {
		t.Fatal("le test ne renomme rien : les deux DN sont identiques")
	}
}

// `entryUUID` est déclaré avec la syntaxe UUID (RFC 4530). Une valeur qui ne
// la respecte pas fait rejeter l'ENTRÉE par un client strict — et retomber sur
// le nom « en attendant » referait le défaut. Donc : absent, jamais faux.
func TestSansUUIDAucunIdentifiantNEstServi(t *testing.T) {
	for _, valeur := range []string{"", "alice", "vaultaire-alice",
		"597AE2F6-16A6-4027-98F4-D28B5365DC14", "pas-un-uuid"} {
		u := compteIdentifie("alice", valeur)
		servis := u.GetAttributes([]string{"*", "+"}, false)
		for _, attr := range attributsIdentifiant {
			if v, present := servis[attr]; present {
				t.Errorf("entry_uuid=%q : %s est servi avec %v — il doit être ABSENT tant que "+
					"la base ne rend pas un UUID bien formé", valeur, attr, v)
			}
		}
		// Le reste de l'entrée ne doit pas en souffrir.
		if len(servis["uid"]) != 1 {
			t.Errorf("entry_uuid=%q : uid n'est plus servi", valeur)
		}
	}
}

// Les cinq noms portent la MÊME valeur, bien formée, et ne sortent que
// demandés : ils sont opérationnels (RFC 4511 §4.5.1).
func TestLesCinqNomsPortentLeMemeUUID(t *testing.T) {
	u := compteIdentifie("alice", uuidDAlice)

	if fuite := u.GetAttributes([]string{"*"}, false); len(fuite[AttrEntryUUID]) != 0 {
		t.Errorf("« * » rend entryUUID : un attribut opérationnel ne sort que demandé")
	}

	servis := u.GetAttributes([]string{"+"}, false)
	var noms []string
	for _, attr := range attributsIdentifiant {
		v := servis[attr]
		if len(v) != 1 || v[0] != uuidDAlice {
			t.Errorf("%s = %v, attendu [%s]", attr, v, uuidDAlice)
			continue
		}
		if !identifiant.EstUnUUID(v[0]) {
			t.Errorf("%s = %q n'a pas la forme d'un UUID", attr, v[0])
		}
		noms = append(noms, attr)
	}
	sort.Strings(noms)
	if len(noms) != 5 {
		t.Errorf("identifiants servis : %v — cinq attendus", noms)
	}
}

// Un groupe porte lui aussi son identifiant, et lui seul : pas les alias
// propriétaires, qu'aucun client ne cherche sur un groupe sans chercher
// d'abord `entryUUID`.
func TestUnGroupePorteSonIdentifiant(t *testing.T) {
	const uuidDuGroupe = "0c7e2f1a-9b3d-4e55-8a61-3f2b9d4c7e10"
	g := GroupEntry{Name: "admins", BaseDN: "enov.local", EntryUUID: uuidDuGroupe,
		Members: []string{"uid=alice,ou=users,dc=enov,dc=local"}}

	if v := g.GetAttribute(AttrEntryUUID); len(v) != 1 || v[0] != uuidDuGroupe {
		t.Errorf("entryUUID du groupe = %v, attendu [%s]", v, uuidDuGroupe)
	}
	if v := g.GetAttributes([]string{"*"}, false)[AttrEntryUUID]; len(v) != 0 {
		t.Errorf("« * » rend l'entryUUID du groupe : il est opérationnel")
	}
	g.EntryUUID = ""
	if v := g.GetAttributes([]string{"+"}, false)[AttrEntryUUID]; len(v) != 0 {
		t.Errorf("un groupe sans UUID sert entryUUID = %v : il doit être absent", v)
	}
}
