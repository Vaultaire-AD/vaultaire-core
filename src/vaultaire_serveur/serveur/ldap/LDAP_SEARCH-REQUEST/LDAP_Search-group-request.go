package ldapsearchrequest

import (
	"DUCKY/serveur/database"
	"DUCKY/serveur/domain"
	ldaptools "DUCKY/serveur/ldap/LDAP-TOOLS"
	ldapstorage "DUCKY/serveur/ldap/LDAP_Storage"
	"DUCKY/serveur/logs"
	"DUCKY/serveur/storage"
	"database/sql"
	"fmt"
	"log"
	"net"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func SearchGroupRequest(conn net.Conn, messageID int, db *sql.DB, dn string, filtres []ldapstorage.EqualityFilter, baseObject string) {

	if filtres[0].Attribute == "cn" {
		//ici on cherche a recup les user present dans 1 groupe
		fmt.Println("→ Déclenchement du traitement pour les **groupeName**")
		SearchGroupNameRequest(conn, messageID, filtres[0].Value)
		return
	}
	if filtres[0].Attribute == "member" {
		fmt.Println("→ Déclenchement du traitement pour les **membres**")
		dn := filtres[0].Value                              // "uid=fiona,dc=it,dc=company,dc=com"
		uid, _, _ := ldaptools.ExtractUsernameAndDomain(dn) // => "fiona"
		groups, err := database.FindGroupsByUserInDomainTree(database.GetDatabase(), uid, baseObject)
		if err != nil {
			log.Println("Erreur récupération groupes :", err)
			SendLDAPSearchFailure(conn, messageID, "Erreur interne")
			return
		}
		groupInfos, err := database.GetGroupsWithUsersByNames(database.GetDatabase(), groups)
		if err != nil {
			logs.Write_Log("ERROR", "failed to get groups with users: "+err.Error())
			return
		}
		SendGroupSearchEntries(conn, messageID, groupInfos)
		return
	}

	groups, err := domain.GetGroupsUnderDomain(dn, database.GetDatabase())
	if err != nil {
		logs.Write_Log("WARNING", "error during the retrieval of groups under domain: "+err.Error())
		return
	}

	groupInfos, err := database.GetGroupsWithUsersByNames(database.GetDatabase(), groups)
	if err != nil {
		logs.Write_Log("ERROR", "failed to get groups with users: "+err.Error())
		return
	}
	SendGroupSearchEntries(conn, messageID, groupInfos)

}
func SendGroupSearchEntries(conn net.Conn, messageID int, groupInfos []ldapstorage.Group) {
	for _, group := range groupInfos {
		if storage.Ldap_Debug {
			fmt.Println("sgroup send to client : " + group.GroupName)
		}
		logs.Write_Log("DEBUG", fmt.Sprintf("Sending group '%s' with users: %v to %s", group.GroupName, group.Users, conn.RemoteAddr().String()))
		dn := fmt.Sprintf("cn=%s,dc=%s", group.GroupName, group.DomainName)

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

		_, err := conn.Write(packet.Bytes())
		if err != nil {
			logs.Write_Log("ERROR", fmt.Sprintf("Failed to write SearchResultEntry for group '%s': %v", group.GroupName, err))
			continue
		}
	}

	// Envoie final du SearchResultDone
	SendLDAPSearchResultDone(conn, messageID)
}

func SendLDAPSearchResultDone(conn net.Conn, messageID int) {
	// Send SearchResultDone
	resultDone := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 5, nil, "SearchResultDone")
	resultDone.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "resultCode"))
	resultDone.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	resultDone.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))

	finalPacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Message")
	finalPacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, uint64(messageID), "Message ID"))
	finalPacket.AppendChild(resultDone)

	logs.Write_Log("DEBUG", fmt.Sprintf("Sending SearchResultDone, packet length: %d bytes", len(finalPacket.Bytes())))
	n, err := conn.Write(finalPacket.Bytes())
	if err != nil {
		logs.Write_Log("ERROR", fmt.Sprintf("Error writing SearchResultDone: %v", err))
		return
	}
	logs.Write_Log("DEBUG", fmt.Sprintf("Sent %d bytes for SearchResultDone", n))
}
