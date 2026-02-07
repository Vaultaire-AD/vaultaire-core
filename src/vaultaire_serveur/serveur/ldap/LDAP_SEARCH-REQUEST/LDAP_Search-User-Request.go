package ldapsearchrequest

import (
	"vaultaire/serveur/database"
	"vaultaire/serveur/domain"
	ldaptools "vaultaire/serveur/ldap/LDAP-TOOLS"
	ldapstorage "vaultaire/serveur/ldap/LDAP_Storage"
	"vaultaire/serveur/logs"
	"fmt"
	"net"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func SendUserSearchRequest(userResponses []map[string]string, conn net.Conn, messageID int) {
	if len(userResponses) == 0 {
		logs.Write_Log("DEBUG", "No users found for given groups")
		err := SendLDAPSearchFailure(conn, messageID, "No users found for given group")
		if err != nil {
			logs.Write_Log("ERROR", "Error sending LDAP search failure: "+err.Error())
		}
		return
	}

	for _, userMap := range userResponses {
		username, ok := userMap["uid"]
		if !ok {
			logs.Write_Log("ERROR", "Missing 'uid' in user entry")
			continue
		}

		comment := userMap["description"] // facultatif
		baseDN := ldaptools.ConvertLDAPBaseToDomainName(comment)
		dn := fmt.Sprintf("uid=%s,ou=users,%s", username, baseDN)

		attrs := make(map[string][]string)
		for attr, value := range userMap {
			attrs[attr] = []string{value}
		}

		entry := buildSearchEntryPacket(dn, attrs)
		response := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 4, nil, "SearchResultEntry")
		response.AppendChild(entry.Children[0])
		response.AppendChild(entry.Children[1])

		packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
		packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, uint64(messageID), "Message ID"))
		packet.AppendChild(response)

		logs.Write_Log("DEBUG", fmt.Sprintf("Sending SearchResultEntry for user '%s', packet length: %d bytes", username, len(packet.Bytes())))
		_, err := conn.Write(packet.Bytes())
		if err != nil {
			logs.Write_Log("ERROR", fmt.Sprintf("Error writing SearchResultEntry for user '%s': %v", username, err))
			return
		}
		// logs.Write_Log("DEBUG", fmt.Sprintf("Sent %d bytes for user '%s'", n, username))
	}

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

func buildSearchEntryPacket(dn string, attributes map[string][]string) *ber.Packet {
	entry := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "SearchResultEntry")
	entry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "DN"))

	attrsSeq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")

	for attrName, values := range attributes {
		attr := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "PartialAttribute")
		attr.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, attrName, "Type"))

		valueSet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "Values")
		for _, v := range values {
			valueSet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, "Value"))
		}
		attr.AppendChild(valueSet)
		attrsSeq.AppendChild(attr)
	}

	entry.AppendChild(attrsSeq)
	return entry
}

func PrepareUserResponseSmart(
	user ldapstorage.User,
	requestedAttrs []string,
	ctx AttrContext,
	typesOnly bool,
) map[string]string {

	userMap := make(map[string]string)

	// ← Ici on ajoute l'étape 2
	if typesOnly {
		// TypesOnly = true → on renvoie au minimum 'uid' et éventuellement d'autres attributs de base
		userMap["uid"] = user.Username
		userMap["displayname"] = strings.TrimSpace(user.Firstname + " " + user.Lastname)
		userMap["mail"] = user.Email
		return userMap
	}

	for _, attr := range requestedAttrs {
		key := strings.ToLower(attr)

		resolver, ok := userAttributeResolvers[key]
		if !ok {
			continue // attribut non supporté → ignoré
		}

		if value, ok := resolver(user, ctx); ok {
			userMap[attr] = value
		}
	}

	return userMap
}

func PrepareUserResponses(
	users []ldapstorage.User,
	requestedAttrs []string,
	baseDN string,
	typeonly bool,
) []map[string]string {

	responses := make([]map[string]string, 0, len(users))

	for _, u := range users {

		groups, _ := database.FindGroupsByUserInDomainTree(
			database.GetDatabase(),
			u.Username,
			baseDN,
		)

		ctx := AttrContext{
			BaseDN: baseDN,
			Groups: groups,
		}

		userMap := PrepareUserResponseSmart(u, requestedAttrs, ctx, typeonly)
		logs.Write_Log("DEBUG", "[LDAP] User response map: "+fmt.Sprint(userMap))
		responses = append(responses, userMap)
	}

	return responses
}

func SearchUserRequest(conn net.Conn, messageID int, dn string, attribute []string, filtres []ldapstorage.EqualityFilter, scope int, typeonly bool) {
	// ici c'est pour les recherche sur 1 user precies

	uidFound := false
	var responses []map[string]string
	var err error
	for _, filtre := range filtres {
		if strings.ToLower(filtre.Attribute) == "uid" {
			uidFound = true
			fmt.Println("→ Déclenchement du traitement pour le uid :", filtre.Value)

			user, err := database.GetUserByUsername(filtre.Value, database.GetDatabase())
			if err != nil {
				logs.Write_Log("WARNING", "error during the retrieval of users by groups: "+err.Error())
				err := SendLDAPSearchFailure(conn, messageID, "error during the retrieval of users by groups")
				if err != nil {
					logs.Write_Log("ERROR", "Error sending LDAP search failure: "+err.Error())
				}
				return
			}
			groups, _ := database.FindGroupsByUserInDomainTree(
				database.GetDatabase(),
				user.Username,
				dn,
			)

			ctx := AttrContext{
				BaseDN: dn,
				Groups: groups,
			}

			responses = append(
				responses,
				PrepareUserResponseSmart(user, attribute, ctx, typeonly),
			)

		}
	}

	if uidFound {
		SendUserSearchRequest(responses, conn, messageID)
		return
	}
	logs.Write_Log("INFO", fmt.Sprintf("Handling SearchUserRequest for DN: %s, messageID: %d", dn, messageID))

	groups, err := domain.GetGroupsUnderDomain(dn, database.GetDatabase(), false)
	if err != nil {
		logs.Write_Log("WARNING", "error during the retrieval of groups under domain: "+err.Error())
		err := SendLDAPSearchFailure(conn, messageID, "error during the retrieval of groups under domain")
		if err != nil {
			logs.Write_Log("ERROR", "Error sending LDAP search failure: "+err.Error())
		}
		return
	}

	Users, err := database.GetUsersByGroups(groups, database.GetDatabase())
	if err != nil {
		logs.Write_Log("WARNING", "error during the retrieval of users by groups: "+err.Error())
		err := SendLDAPSearchFailure(conn, messageID, "error during the retrieval of users by groups: ")
		if err != nil {
			logs.Write_Log("ERROR", "Error sending LDAP search failure: "+err.Error())
		}
		return
	}

	responses = PrepareUserResponses(Users, attribute, dn, typeonly)

	logs.Write_Log("INFO", fmt.Sprintf("Found %d users for groups under domain %s", len(responses), dn))

	SendUserSearchRequest(responses, conn, messageID)
}
