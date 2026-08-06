package ldaptools

import "testing"

// TestIsRootDSEBase fige la règle de détection des bases spéciales.
//
// Elle était écrite à trois endroits avec trois comportements. L'écart avait un
// effet concret : « CN=Schema » passait le contrôle qui exigeait un bind —
// comparaison sensible à la casse — mais échappait au contrôle d'autorisation
// qui suivait, lui insensible à la casse.
func TestIsRootDSEBase(t *testing.T) {
	speciales := []string{
		"", "  ",
		"cn=schema", "CN=SCHEMA", "Cn=Schema", " cn=schema ",
		"cn=subschema", "CN=Subschema",
	}
	for _, base := range speciales {
		if !IsRootDSEBase(base) {
			t.Errorf("IsRootDSEBase(%q) = false, attendu true", base)
		}
	}

	ordinaires := []string{
		"dc=vaultaire,dc=fr",
		"ou=users,dc=vaultaire,dc=fr",
		"uid=alice,ou=users,dc=vaultaire,dc=fr",
		"cn=schemas,dc=vaultaire,dc=fr", // proche, mais bien une entrée
		"cn=schema,dc=vaultaire,dc=fr",  // le schéma n'a pas de parent
	}
	for _, base := range ordinaires {
		if IsRootDSEBase(base) {
			t.Errorf("IsRootDSEBase(%q) = true, attendu false", base)
		}
	}
}

// TestGetDefaultRootDNSansBase : le RootDSE répond même sans base.
//
// C'est la seule chose qu'un client obtient AVANT de s'authentifier. Ce chemin
// déréférençait un *sql.DB nil et arrêtait le serveur entier sur une requête de
// découverte envoyée par un inconnu.
func TestGetDefaultRootDNSansBase(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("PANIQUE sans base de données : %v", r)
		}
	}()

	// Aucune base initialisée dans ce test : GetDatabase() rend nil.
	got := GetDefaultRootDN()
	if len(got) == 0 {
		t.Fatal("aucune racine rendue : un client ne saurait pas quoi interroger")
	}
	if got[0] != DefaultRootDN {
		t.Errorf("racine de repli = %q, attendu %q", got[0], DefaultRootDN)
	}
}
