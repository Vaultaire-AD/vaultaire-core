package commandcertificate

import (
	"testing"

	duckykey "vaultaire/ducky-network/key_management"
)

// Ces tests gardent une seule chose, mais celle qui a déjà été perdue une fois :
// que le portail et l'API soient ATTEIGNABLES par la commande.
//
// Leur certificat est produit au premier démarrage puis conservé en base. Tant
// que `regenerate` refusait tout nom autre que LDAPS, une déclaration
// `web_tls_dns_names` ajoutée après coup restait sans effet — et le correctif
// d'identité des certificats, pourtant écrit et testé, était inatteignable sur
// toute installation déjà démarrée.
//
// Une faute de frappe dans `nomCanonique` ou une entrée manquante dans
// `certificatsRegenerables` rétablirait exactement cette situation, sans rien
// casser de visible.

func TestLesRaccourcisDesignentLeBonCertificat(t *testing.T) {
	cas := map[string]string{
		"ldaps":        duckykey.LDAPSServerCertName,
		"ldap":         duckykey.LDAPSServerCertName,
		"ldaps_server": duckykey.LDAPSServerCertName,
		"web":          duckykey.WebServerCertName,
		"WEB":          duckykey.WebServerCertName,
		"portail":      duckykey.WebServerCertName,
		"sso":          duckykey.WebServerCertName,
		"web_server":   duckykey.WebServerCertName,
		"api":          duckykey.APIServerCertName,
		"rest":         duckykey.APIServerCertName,
		"api_server":   duckykey.APIServerCertName,
		"all":          "all",
		"tous":         "all",
		"  web  ":      duckykey.WebServerCertName,
	}
	for saisi, attendu := range cas {
		if got := nomCanonique(saisi); got != attendu {
			t.Errorf("nomCanonique(%q) = %q, attendu %q", saisi, got, attendu)
		}
	}
}

func TestLesTroisCertificatsSontRegenerables(t *testing.T) {
	for _, nom := range []string{
		duckykey.LDAPSServerCertName,
		duckykey.WebServerCertName,
		duckykey.APIServerCertName,
	} {
		info, ok := certificatsRegenerables[nom]
		if !ok {
			t.Fatalf("%q absent de certificatsRegenerables : la commande le refusera", nom)
		}
		if info.description == "" || info.service == "" {
			t.Errorf("%q : description ou service vide, le compte rendu serait muet", nom)
		}
	}
}

// TestUnNomInconnuResteRefuse : le fail-closed ne doit pas avoir été perdu en
// élargissant la liste. Un nom quelconque ne doit pas créer un certificat.
func TestUnNomInconnuResteRefuse(t *testing.T) {
	if _, ok := certificatsRegenerables[nomCanonique("nimporte_quoi")]; ok {
		t.Fatal("un nom inconnu est accepté comme certificat régénérable")
	}
}
