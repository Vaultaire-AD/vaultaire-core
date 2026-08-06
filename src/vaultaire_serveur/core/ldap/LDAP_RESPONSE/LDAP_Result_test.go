package ldapresponse

import (
	"strings"
	"testing"

	ldapstorage "vaultaire/core/ldap/LDAP_Storage"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// TestLonguesChainesNeTronquentPas couvre le point 2.6.
//
// Les réponses de bind et d'ExtendedRequest étaient encodées à la main :
//
//	full := []byte{0x30, byte(len(payload))}
//
// BER exige la forme longue au-delà de 127 octets, et `byte()` tronque au-delà
// de 255. Un message de diagnostic un peu long produisait un paquet malformé, et
// le symptôme apparaissait côté client, loin de la cause.
//
// Le test emploie des tailles qui franchissent les deux seuils.
func TestLonguesChainesNeTronquentPas(t *testing.T) {
	for _, taille := range []int{10, 127, 128, 255, 256, 1000} {
		diagnostic := strings.Repeat("d", taille)

		paquet := BuildResult(1, ldapstorage.AppBindResponse,
			ldapstorage.ResultInvalidCredentials, "", diagnostic)

		// Le paquet doit rester plus grand que sa charge : une longueur tronquée
		// produirait un paquet plus court que ce qu'il prétend contenir.
		if len(paquet) <= taille {
			t.Errorf("diagnostic de %d octets : paquet de %d octets, tronqué",
				taille, len(paquet))
		}

		// Et il doit rester décodable.
		if p := ber.DecodePacket(paquet); p == nil {
			t.Errorf("diagnostic de %d octets : paquet indécodable", taille)
		}
	}
}

// TestExtendedResultOmetLesChampsVides.
//
// responseName [10] et responseValue [11] sont OPTIONAL dans la RFC 4511. Un
// champ vide PRÉSENT n'a pas le même sens qu'un champ ABSENT : certains clients
// lisent un responseName vide comme une extension inconnue.
func TestExtendedResultOmetLesChampsVides(t *testing.T) {
	sans := BuildExtendedResult(1, ldapstorage.ResultSuccess, "", "", "", "")
	avec := BuildExtendedResult(1, ldapstorage.ResultSuccess, "", "", "", "dn:uid=alice,ou=system")

	if len(avec) <= len(sans) {
		t.Errorf("responseValue non transmis : %d octets avec, %d sans", len(avec), len(sans))
	}
	if ber.DecodePacket(sans) == nil || ber.DecodePacket(avec) == nil {
		t.Error("paquet indécodable")
	}
}
