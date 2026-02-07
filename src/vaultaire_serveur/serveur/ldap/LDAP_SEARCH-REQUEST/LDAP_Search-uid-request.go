package ldapsearchrequest

import (
	"vaultaire/serveur/database"
	ldaptools "vaultaire/serveur/ldap/LDAP-TOOLS"
	"fmt"
	"log"
	"net"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
)

type PartialAttribute struct {
	Type string
	Vals []string
}

type SearchResultEntry struct {
	ObjectName string
	Attributes []PartialAttribute
}

func SendLDAPSearchResultEntry(conn net.Conn, messageID int, entry SearchResultEntry) error {
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

	_, err := conn.Write(packet.Bytes())
	return err
}

func SendUidSearchRequest(uid string, domain string, Attributes []string, conn net.Conn, messageID int) {
	userDN := fmt.Sprintf("uid=%s,dc=%s", uid, strings.ReplaceAll(domain, ".", ",dc="))
	user, err := database.GetUserByUsername(uid, database.GetDatabase())
	if err != nil {
		log.Println("Erreur lors de la récupération de l'utilisateur :", err)
		SendLDAPSearchFailure(conn, messageID, "Utilisateur non trouvé")
		return
	}

	createdate, _ := ldaptools.SQLDateToLDAPFormat(user.Created_at)
	db := database.GetDatabase()

	// Récupérer les DN des groupes de l'utilisateur
	groupIDs, _ := database.Command_GET_UserGroupIDs(db, uid)
	groupDNs := []string{}
	for _, gid := range groupIDs {
		gi, err := database.GetGroupInfoByID(db, gid)
		if err != nil {
			continue
		}
		groupDN := fmt.Sprintf("cn=%s,ou=groups,dc=%s", gi.Name, strings.ReplaceAll(gi.DomainName, ".", ",dc="))
		groupDNs = append(groupDNs, groupDN)

		// Envoyer directement les groupes pour pfSense
		// groupEntry := SearchResultEntry{
		// 	ObjectName: groupDN,
		// 	Attributes: []PartialAttribute{
		// 		{Type: "cn", Vals: []string{gi.Name}},
		// 		{Type: "objectClass", Vals: []string{"groupOfNames"}},
		// 		{Type: "member", Vals: []string{userDN}},
		// 	},
		// }
		// SendLDAPSearchResultEntry(conn, messageID, groupEntry)
	}

	// Construction de l'entrée utilisateur
	userAttributes := []PartialAttribute{
		{Type: "uid", Vals: []string{uid}},
		{Type: "cn", Vals: []string{user.Firstname}},
		{Type: "sn", Vals: []string{user.Lastname}},
		{Type: "objectClass", Vals: []string{"inetOrgPerson", "posixAccount"}},
		{Type: "mail", Vals: []string{user.Email}},
		{Type: "whenCreated", Vals: []string{createdate}},
	}

	if contains(Attributes, "memberOf") && len(groupDNs) > 0 {
		userAttributes = append(userAttributes, PartialAttribute{Type: "memberOf", Vals: groupDNs})
	}

	entry := SearchResultEntry{ObjectName: userDN, Attributes: userAttributes}
	if err := SendLDAPSearchResultEntry(conn, messageID, entry); err != nil {
		log.Println("Erreur en envoyant l'entrée LDAP :", err)
		return
	}

	SendLDAPSearchResultDone(conn, messageID)
}

// helper pour vérifier si un slice contient une string
func contains(slice []string, str string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, str) {
			return true
		}
	}
	return false
}
