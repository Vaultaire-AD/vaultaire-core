package ldapsearchrequest

import (
	"vaultaire/serveur/database"
	ldapstorage "vaultaire/serveur/ldap/LDAP_Storage"
	"vaultaire/serveur/logs"
	"fmt"
	"net"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func SearchGroupNameRequest(conn net.Conn, messageID int, groupName string) {
	group, err := database.GetGroupWithUsersByName(database.GetDatabase(), groupName)
	if err != nil {
		logs.Write_Log("ERROR", "failed to get groups with users: "+err.Error())
		fmt.Println("ERROR failed to get groups with user: " + err.Error())
		return
	}

	// Compose DN du groupe (exemple)
	dn := fmt.Sprintf("cn=%s,dc=%s", group.GroupName, group.DomainName)
	logs.Write_Log("DEBUG", fmt.Sprintf("ldap: search group cn=%s,dc=%s users=%v", group.GroupName, group.DomainName, group.Users))
	groupattr := ldapstorage.Group{
		GroupName: group.GroupName,
		Users:     group.Users,
	}

	attrs := ldapstorage.GetGroupAttrs(groupattr)

	entry := buildSearchEntryPacket(dn, attrs)

	response := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 4, nil, "SearchResultEntry")
	response.AppendChild(entry.Children[0]) // DN
	response.AppendChild(entry.Children[1]) // Attributes

	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, uint64(messageID), "Message ID"))
	packet.AppendChild(response)

	_, err = conn.Write(packet.Bytes())
	if err != nil {
		logs.Write_Log("ERROR", fmt.Sprintf("Failed to write SearchResultEntry for group '%s': %v", group.GroupName, err))
		return
	}

	SendLDAPSearchResultDone(conn, messageID)
}

// if foundCategories["groupname"] {
// 	//ici on cherche a recup les user present dans 1 groupe
// 	fmt.Println("→ Déclenchement du traitement pour les **groupeName**")
// 	SearchGroupNameRequest(conn, messageID, groupName)
// }
