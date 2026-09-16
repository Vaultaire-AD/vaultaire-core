// Package ldapresponse construit les réponses LDAPResult.
//
// # Pourquoi un paquet à part
//
// Trois fichiers encodaient leurs réponses à la main, avec des longueurs BER sur
// un octet :
//
//	matched := []byte{0x04, byte(len(matchedDN))}
//	full := []byte{0x30, byte(len(payload))}
//
// BER exige la forme longue au-delà de 127 octets, et `byte()` tronque
// silencieusement au-delà de 255. Tant que les messages restaient courts, ça
// tenait. Un message de diagnostic un peu long produisait un paquet malformé, et
// le symptôme apparaissait côté client, loin de la cause.
//
// Le reste du paquet LDAP utilise déjà `ber.Encode`, qui gère les longueurs. Il
// n'y avait aucune raison de garder deux façons d'encoder la même chose.
package ldapresponse

import (
	"fmt"
	"net"

	ldapstorage "vaultaire/core/ldap/LDAP_Storage"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// BuildResult encode un LDAPMessage portant un LDAPResult.
//
// C'est la structure commune à BindResponse, SearchResultDone, ModifyResponse et
// toutes les autres réponses d'opération : un code, un matchedDN, un message de
// diagnostic. Seule l'étiquette d'application change.
func BuildResult(messageID, appTag, resultCode int, matchedDN, diagnostic string) []byte {
	result := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(appTag), nil, "LDAPResult")
	result.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated,
		uint64(resultCode), "resultCode"))
	result.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString,
		matchedDN, "matchedDN"))
	result.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString,
		diagnostic, "diagnosticMessage"))

	message := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	message.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger,
		uint64(messageID), "messageID"))
	message.AppendChild(result)
	return message.Bytes()
}

// SendResult envoie un LDAPResult.
func SendResult(conn net.Conn, messageID, appTag, resultCode int, matchedDN, diagnostic string) error {
	if _, err := conn.Write(BuildResult(messageID, appTag, resultCode, matchedDN, diagnostic)); err != nil {
		return fmt.Errorf("envoi de la réponse LDAP : %w", err)
	}
	return nil
}

// BuildExtendedResult encode une ExtendedResponse, avec ses deux champs
// facultatifs.
//
// responseName porte l'étiquette contextuelle [10] et responseValue [11]. Ils
// sont omis quand ils sont vides — la RFC les déclare OPTIONAL, et un champ vide
// présent n'a pas le même sens qu'un champ absent.
func BuildExtendedResult(messageID, resultCode int, matchedDN, diagnostic, responseName, responseValue string) []byte {
	result := ber.Encode(ber.ClassApplication, ber.TypeConstructed,
		ber.Tag(ldapstorage.AppExtendedResponse), nil, "ExtendedResponse")
	result.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated,
		uint64(resultCode), "resultCode"))
	result.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString,
		matchedDN, "matchedDN"))
	result.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString,
		diagnostic, "diagnosticMessage"))

	if responseName != "" {
		result.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 10,
			responseName, "responseName"))
	}
	if responseValue != "" {
		result.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 11,
			responseValue, "responseValue"))
	}

	message := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	message.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger,
		uint64(messageID), "messageID"))
	message.AppendChild(result)
	return message.Bytes()
}

// SendExtendedResult envoie une ExtendedResponse.
func SendExtendedResult(conn net.Conn, messageID, resultCode int, matchedDN, diagnostic, responseName, responseValue string) error {
	if _, err := conn.Write(BuildExtendedResult(messageID, resultCode, matchedDN, diagnostic, responseName, responseValue)); err != nil {
		return fmt.Errorf("envoi de l'ExtendedResponse : %w", err)
	}
	return nil
}
