package ldaptools

import "testing"

// Un DN est insensible à la casse sur le NOM de ses attributs (RFC 4514 §3).
//
// Le défaut était discret et coûteux : la reconnaissance du préfixe se faisait
// sur la forme minuscule, le retrait sur la forme d'origine. « DC=Enov » rendait
// donc « DC=Enov » au lieu de « Enov », et le domaine reconstruit ne correspondait
// à rien. Le client voyait un annuaire vide et cherchait du côté de ses droits.
func TestLaCasseDuPrefixeDcNeChangeRien(t *testing.T) {
	cas := map[string]string{
		"dc=enov,dc=local":                    "enov.local",
		"DC=Enov,DC=Local":                    "Enov.Local",
		"Dc=enov,dC=local":                    "enov.local",
		"ou=users,DC=enov,DC=local":           "enov.local",
		"OU=Users,DC=Admin,DC=Enov,DC=Local":  "Admin.Enov.Local",
		"uid=alice,ou=users,dc=enov,dc=local": "enov.local",
	}

	for base, attendu := range cas {
		if obtenu := ConvertLDAPBaseToDomainName(base); obtenu != attendu {
			t.Errorf("%q => %q, attendu %q", base, obtenu, attendu)
		}
	}
}

// La VALEUR garde sa casse : c'est la donnée du client, pas à nous de la
// réécrire. Les comparaisons de domaines la normalisent chacune de leur côté.
func TestLaValeurGardeSaCasse(t *testing.T) {
	if d := ConvertLDAPBaseToDomainName("DC=Enov,DC=Local"); d != "Enov.Local" {
		t.Errorf("%q : la valeur a été réécrite", d)
	}
}

// Ce qui ne porte aucun composant de domaine ne rend rien — et surtout pas une
// chaîne qui aurait l'air d'un domaine.
func TestSansComposantDcOnNeRendRien(t *testing.T) {
	for _, base := range []string{"", "cn=schema", "ou=users", "o=acme,c=fr", "dc="} {
		if d := ConvertLDAPBaseToDomainName(base); d != "" {
			t.Errorf("%q => %q, attendu une chaîne vide", base, d)
		}
	}
}
