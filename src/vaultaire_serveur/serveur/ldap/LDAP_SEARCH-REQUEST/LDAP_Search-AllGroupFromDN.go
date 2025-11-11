package ldapsearchrequest

import (
	"DUCKY/serveur/database"
	"DUCKY/serveur/domain"
	"DUCKY/serveur/logs"
	"fmt"
	"net"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// SearchAllUsersFromGroups récupère tous les utilisateurs via les groupes sous un domaine
func SearchGroupsForCNUsers(conn net.Conn, messageID int, baseDomain string) {
	logs.Write_Log("INFO", fmt.Sprintf("Handling SearchGroupsForCNUsers for domain: %s", baseDomain))

	// 1️⃣ Récupérer tous les groupes sous le domaine
	groups, err := domain.GetGroupsUnderDomain(baseDomain, database.GetDatabase())
	if err != nil {
		logs.Write_Log("WARNING", "Erreur récupération des groupes : "+err.Error())
		_ = SendLDAPSearchFailure(conn, messageID, "Erreur interne lors de la récupération des groupes")
		return
	}
	if len(groups) == 0 {
		logs.Write_Log("INFO", "Aucun groupe trouvé sous le domaine "+baseDomain)
		_ = SendLDAPSearchFailure(conn, messageID, "Aucun groupe trouvé sous le domaine")
		return
	}

	// 2️⃣ Préparer la réponse LDAP pour chaque groupe
	var responses []map[string]string
	for _, g := range groups {
		responses = append(responses, map[string]string{
			"cn":          g,
			"objectClass": "groupOfNames",
		})
	}

	logs.Write_Log("INFO", fmt.Sprintf("Found %d groups under domain %s", len(responses), baseDomain))

	// 3️⃣ Envoyer les groupes au client
	SendGroupSearchRequest(conn, messageID, responses)
}

// SendGroupSearchRequest envoie une liste de groupes au client LDAP (slice de maps)
func SendGroupSearchRequest(conn net.Conn, messageID int, groups []map[string]string) {
	if len(groups) == 0 {
		logs.Write_Log("DEBUG", "No groups found for given domain")
		_ = SendLDAPSearchFailure(conn, messageID, "No groups found")
		return
	}

	for _, group := range groups {
		groupName := group["cn"]
		logs.Write_Log("DEBUG", fmt.Sprintf("Sending group '%s' to %s", groupName, conn.RemoteAddr().String()))

		dn := fmt.Sprintf("cn=%s,dc=%s", groupName, group["dc"]) // adapte si besoin

		// ✅ Convert map[string]string -> map[string][]string
		attrs := make(map[string][]string)
		for k, v := range group {
			attrs[k] = []string{v}
		}

		entry := buildSearchEntryPacket(dn, attrs)

		response := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 4, nil, "SearchResultEntry")
		response.AppendChild(entry.Children[0])
		response.AppendChild(entry.Children[1])

		packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
		packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, uint64(messageID), "Message ID"))
		packet.AppendChild(response)

		_, err := conn.Write(packet.Bytes())
		if err != nil {
			logs.Write_Log("ERROR", fmt.Sprintf("Failed to write SearchResultEntry for group '%s': %v", groupName, err))
			continue
		}
	}

	// Envoi final du SearchResultDone
	sendLDAPSearchResultDone(conn, messageID)
}

// SendLDAPSearchResultDone envoie le message LDAP SearchResultDone
func sendLDAPSearchResultDone(conn net.Conn, messageID int) {
	resultDone := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 5, nil, "SearchResultDone")
	resultDone.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "resultCode"))
	resultDone.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	resultDone.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))

	finalPacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Message")
	finalPacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, uint64(messageID), "Message ID"))
	finalPacket.AppendChild(resultDone)

	logs.Write_Log("DEBUG", fmt.Sprintf("Sending SearchResultDone for groups, packet length: %d bytes", len(finalPacket.Bytes())))
	_, err := conn.Write(finalPacket.Bytes())
	if err != nil {
		logs.Write_Log("ERROR", fmt.Sprintf("Error writing SearchResultDone: %v", err))
	}
}
