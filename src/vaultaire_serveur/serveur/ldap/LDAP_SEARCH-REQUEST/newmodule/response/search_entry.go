package response

import (
	"DUCKY/serveur/ldap/LDAP_SEARCH-REQUEST/newmodule/ldap_types"
	"fmt"
	"net"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// SearchResultEntry et PartialAttribute viennent du package ldapsearchrequest
// type SearchResultEntry struct {
//     ObjectName string
//     Attributes []PartialAttribute
// }
// type PartialAttribute struct {
//     Type string
//     Vals []string
// }

func SendLDAPSearchResultEntry(conn net.Conn, messageID int, entry ldap_types.SearchResultEntry) error {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, uint64(messageID), "Message ID"))

	entryPacket := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 4, nil, "SearchResultEntry")
	entryPacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, entry.ObjectName, "ObjectName"))

	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	for _, attr := range entry.Attributes {
		attrSeq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "PartialAttribute")
		attrSeq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, attr.Type, "Type"))

		vals := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "Set")
		for _, val := range attr.Vals {
			vals.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, val, "Value"))
		}

		attrSeq.AppendChild(vals)
		attrs.AppendChild(attrSeq)
	}

	entryPacket.AppendChild(attrs)
	packet.AppendChild(entryPacket)

	// fmt.Println(formatHex(packet.Bytes())) // debug : trame complète avant envoi

	_, err := conn.Write(packet.Bytes())
	if err != nil {
		return fmt.Errorf("failed to send SearchResultEntry: %v", err)
	}

	return nil
}

func formatHex(data []byte) string {
	var s string
	for i := 0; i < len(data); i += 16 {
		end := i + 16
		if end > len(data) {
			end = len(data)
		}
		line := data[i:end]
		hexPart := ""
		asciiPart := ""
		for _, b := range line {
			hexPart += fmt.Sprintf("%02X ", b)
			if b >= 32 && b <= 126 {
				asciiPart += string(b)
			} else {
				asciiPart += "."
			}
		}
		s += fmt.Sprintf("%08X  %-48s  %s\n", i, hexPart, asciiPart)
	}
	return s
}
