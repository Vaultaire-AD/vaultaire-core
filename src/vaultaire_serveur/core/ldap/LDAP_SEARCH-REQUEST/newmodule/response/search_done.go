package response

import (
	"fmt"
	"net"

	ldapjournal "vaultaire/core/ldap/LDAP_Journal"
	ldapstorage "vaultaire/core/ldap/LDAP_Storage"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func SendLDAPSearchResultDone(conn net.Conn, messageID int) error {
	ldapjournal.Resultat(conn, messageID, ldapstorage.ResultSuccess)
	resultDone := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 5, nil, "SearchResultDone")
	resultDone.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "resultCode"))
	resultDone.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	resultDone.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))

	finalPacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Message")
	finalPacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, uint64(messageID), "Message ID"))
	finalPacket.AppendChild(resultDone)

	_, err := conn.Write(finalPacket.Bytes())
	if err != nil {
		return fmt.Errorf("failed to send SearchResultDone: %v", err)
	}
	return nil
}

// SendLDAPSearchResultDonePage termine une page d'une recherche paginée — RFC
// 2696 : un SearchResultDone qui porte, dans les contrôles du message, le
// cookie de la page suivante.
//
//	LDAPMessage ::= SEQUENCE {
//	        messageID   MessageID,
//	        protocolOp  SearchResultDone,
//	        controls    [0] Controls OPTIONAL }
//
// page.Cookie vide dit au client qu'il n'y a plus rien à lire. page.Size est le
// nombre total d'entrées de la recherche — exact ici, le jeu étant figé à la
// première page ; la RFC n'en demande qu'une estimation.
//
// Le code de résultat n'est pas toujours un succès : la dernière page d'une
// recherche qui a atteint une borne porte sizeLimitExceeded, AVEC le contrôle et
// un cookie vide. Le client sait ainsi que la lecture est finie et qu'elle est
// incomplète.
//
// La criticité est omise : elle vaut FALSE par défaut, et la RFC 4511 §4.1.11
// demande de ne pas la mettre dans une réponse.
func SendLDAPSearchResultDonePage(conn net.Conn, messageID, resultCode int, diagnostic string, page ldapstorage.PagedResults) error {
	ldapjournal.Resultat(conn, messageID, resultCode)
	resultDone := ber.Encode(ber.ClassApplication, ber.TypeConstructed,
		ber.Tag(ldapstorage.AppSearchResultDone), nil, "SearchResultDone")
	resultDone.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated,
		uint64(resultCode), "resultCode"))
	resultDone.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	resultDone.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString,
		diagnostic, "diagnosticMessage"))

	// La valeur du contrôle est elle-même du BER, rangé dans une chaîne
	// d'octets : c'est ainsi que tout contrôle transporte ses données.
	valeur := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "realSearchControlValue")
	valeur.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger,
		uint64(page.Size), "size"))
	valeur.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString,
		string(page.Cookie), "cookie"))

	controle := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	controle.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString,
		ldapstorage.OIDPagedResults, "controlType"))
	controle.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString,
		string(valeur.Bytes()), "controlValue"))

	controles := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "Controls")
	controles.AppendChild(controle)

	finalPacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	finalPacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger,
		uint64(messageID), "Message ID"))
	finalPacket.AppendChild(resultDone)
	finalPacket.AppendChild(controles)

	if _, err := conn.Write(finalPacket.Bytes()); err != nil {
		return fmt.Errorf("failed to send paged SearchResultDone: %v", err)
	}
	return nil
}
