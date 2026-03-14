package response

import (
	"fmt"
	"net"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func SendLDAPSearchResultDone(conn net.Conn, messageID int) error {
	resultDone := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 5, nil, "SearchResultDone")
	resultDone.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "resultCode"))
	resultDone.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	resultDone.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))

	finalPacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Message")
	finalPacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, uint64(messageID), "Message ID"))
	finalPacket.AppendChild(resultDone)

	n, err := conn.Write(finalPacket.Bytes())
	if err != nil {
		return fmt.Errorf("failed to send SearchResultDone: %v", err)
	}
	fmt.Printf("Sent %d bytes for SearchResultDone\n", n)
	return nil
}
