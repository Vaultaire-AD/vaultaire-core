package ldapsearchrequest

// func sendSearchEntry(conn net.Conn, messageID int, dn string, attributes map[string]string) error {
// 	entry := buildSearchEntry(dn, attributes)

// 	// Wrap in SearchResultEntry (Application[4])
// 	response := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 4, nil, "SearchResultEntry")
// 	response.AppendChild(entry.Children[0]) // DN
// 	response.AppendChild(entry.Children[1]) // Attributes

// 	// Full LDAP message
// 	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
// 	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, uint64(messageID), "Message ID"))
// 	packet.AppendChild(response)

// 	_, err := conn.Write(packet.Bytes())
// 	return err
// }
