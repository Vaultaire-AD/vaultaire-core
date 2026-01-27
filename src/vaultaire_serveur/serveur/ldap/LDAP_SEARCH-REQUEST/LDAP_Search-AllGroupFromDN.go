package ldapsearchrequest

import (
	"DUCKY/serveur/database"
	"DUCKY/serveur/domain"
	"DUCKY/serveur/logs"
	"fmt"
	"net"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// SearchAllUsersFromGroups récupère tous les utilisateurs via les groupes sous un domaine
// SearchGroupsForCNUsers récupère les groupes LDAP sous un domaine selon le scope
func SearchGroupsForCNUsers(conn net.Conn, messageID int, baseDomain string, scope int) {
	logs.Write_Log("INFO", fmt.Sprintf("Handling SearchGroupsForCNUsers for domain: %s (scope=%d)", baseDomain, scope))

	var groups []string
	var err error

	switch scope {
	case 0: // baseObject → retourne uniquement le domaine lui-même
		logs.Write_Log("DEBUG", "Scope = baseObject : returning only the base domain")
		groups = []string{baseDomain}

	case 1: // singleLevel → uniquement les groupes directement sous le domaine
		logs.Write_Log("DEBUG", "Scope = singleLevel : retrieving direct child groups")
		groups, err = domain.GetGroupsDirectlyUnderDomainExact(baseDomain, database.GetDatabase(), true)
		if err != nil {
			logs.Write_Log("ERROR", "Erreur récupération des groupes directs : "+err.Error())
			_ = SendLDAPSearchFailure(conn, messageID, "Erreur interne lors de la récupération des groupes")
			return
		}

	case 2: // wholeSubtree → tous les groupes récursivement
		logs.Write_Log("DEBUG", "Scope = wholeSubtree : retrieving all groups recursively")
		groups, err = domain.GetGroupsUnderDomain(baseDomain, database.GetDatabase(), true)
		if err != nil {
			logs.Write_Log("ERROR", "Erreur récupération des groupes récursifs : "+err.Error())
			_ = SendLDAPSearchFailure(conn, messageID, "Erreur interne lors de la récupération des groupes")
			return
		}

	default:
		logs.Write_Log("WARNING", fmt.Sprintf("Unknown scope value: %d", scope))
		_ = SendLDAPSearchFailure(conn, messageID, fmt.Sprintf("Invalid scope value: %d", scope))
		return
	}

	if len(groups) == 0 {
		logs.Write_Log("INFO", "Aucun groupe trouvé sous le domaine "+baseDomain)
		_ = SendLDAPSearchFailure(conn, messageID, "Aucun groupe trouvé sous le domaine")
		return
	}

	// Préparer les entrées LDAP
	var responses []map[string]string
	for _, g := range groups {
		// g.GroupName n'est pas utilisé ici, seulement g.DomainName pour le DN
		domainParts := strings.Split(g, ".")
		dnParts := ""
		for _, part := range domainParts {
			dnParts += fmt.Sprintf("dc=%s,", part)
		}
		dnParts = strings.TrimSuffix(dnParts, ",") // retirer la dernière virgule

		responses = append(responses, map[string]string{
			"dn":          dnParts,
			"objectClass": "groupOfNames",
		})
	}

	logs.Write_Log("INFO", fmt.Sprintf("Found %d groups (scope=%d) under domain %s", len(responses), scope, baseDomain))

	// Envoyer les groupes au client LDAP
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
		dn := group["dn"] // <- utiliser le DN déjà préparé
		logs.Write_Log("DEBUG", fmt.Sprintf("Sending group with DN '%s' to %s", dn, conn.RemoteAddr().String()))

		attrs := map[string][]string{
			"objectClass": {group["objectClass"]},
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
			logs.Write_Log("ERROR", fmt.Sprintf("Failed to write SearchResultEntry for DN '%s': %v", dn, err))
			continue
		}
	}

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
