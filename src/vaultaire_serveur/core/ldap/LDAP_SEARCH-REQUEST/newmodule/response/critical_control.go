package response

import (
	"fmt"
	"net"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// LDAPResultUnavailableCriticalExtension — RFC 4511 §4.1.11.
//
// Le code que le serveur DOIT renvoyer quand une opération porte un contrôle
// marqué critique qu'il ne sait pas traiter.
const LDAPResultUnavailableCriticalExtension = 12

// SendUnavailableCriticalExtension refuse une opération portant un contrôle
// critique non supporté.
//
// # Pourquoi refuser plutôt qu'ignorer
//
// Ignorer un contrôle critique donne au client une réponse qui a l'air valide
// mais ne respecte pas ce qu'il a demandé. Le cas concret : un client qui
// pagine reçoit le jeu COMPLET sans cookie de pagination. Selon son
// implémentation, il boucle sur la même page ou traite un résultat qu'il croit
// partiel comme s'il était complet.
//
// « Critique » veut précisément dire : si tu ne sais pas faire, n'essaie pas de
// deviner.
//
// Le tag de réponse dépend de l'opération, mais SearchResultDone (5) est accepté
// par les clients pour un refus général et c'est déjà ce qu'emploie le reste du
// paquet.
func SendUnavailableCriticalExtension(conn net.Conn, messageID int, controlType string) error {
	resultDone := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 5, nil, "SearchResultDone")
	resultDone.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated,
		LDAPResultUnavailableCriticalExtension, "resultCode"))
	resultDone.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	resultDone.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString,
		"unsupported critical control: "+controlType, "diagnosticMessage"))

	finalPacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	finalPacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, uint64(messageID), "Message ID"))
	finalPacket.AppendChild(resultDone)

	if _, err := conn.Write(finalPacket.Bytes()); err != nil {
		return fmt.Errorf("failed to send unavailableCriticalExtension: %v", err)
	}
	return nil
}
