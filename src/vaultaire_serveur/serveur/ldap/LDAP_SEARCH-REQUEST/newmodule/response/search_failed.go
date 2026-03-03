package response

import (
	"vaultaire/serveur/logs"
	"fmt"
	"net"

	ber "github.com/go-asn1-ber/asn1-ber"
)

const LDAPResultOperationsError = 1

func SendLDAPSearchFailure(conn net.Conn, messageID int, errMsg string) error {
	resultDone := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 5, nil, "SearchResultDone")
	resultDone.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, LDAPResultOperationsError, "resultCode"))
	resultDone.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	resultDone.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, errMsg, "diagnosticMessage"))

	finalPacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	finalPacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, uint64(messageID), "Message ID"))
	finalPacket.AppendChild(resultDone)

	n, err := conn.Write(finalPacket.Bytes())
	if err != nil {
		return fmt.Errorf("failed to send LDAPSearchFailure: %v", err)
	}
	fmt.Printf("Sent %d bytes for LDAPSearchFailure\n", n)
	logs.Write_Log("WARNING", "Ldap request failed :"+errMsg)
	return nil
}
