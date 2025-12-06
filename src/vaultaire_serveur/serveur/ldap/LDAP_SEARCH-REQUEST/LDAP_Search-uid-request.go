package ldapsearchrequest

import (
	"DUCKY/serveur/database"
	ldaptools "DUCKY/serveur/ldap/LDAP-TOOLS"
	"DUCKY/serveur/logs"
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

func SendUidSearchRequest(uid string, domain string, conn net.Conn, messageID int) {
	// Construction du DN complet de l'utilisateur
	userDN := fmt.Sprintf("uid=%s,dc=%s", uid, strings.ReplaceAll(domain, ".", ",dc="))
	user, err := database.GetUserByUsername(uid, database.GetDatabase())
	if err != nil {
		log.Println("Erreur lors de la récupération de l'utilisateur :", err)
		err := SendLDAPSearchFailure(conn, messageID, "Utilisateur non trouvé")
		if err != nil {
			logs.Write_Log("ERROR", "Error sending LDAP search failure: "+err.Error())
		}
		return

	}
	createdate, _ := ldaptools.SQLDateToLDAPFormat(user.Created_at)
	db := database.GetDatabase()
	groupIDs, _ := database.Command_GET_UserGroupIDs(db, uid)
	groupDNs := []string{}

	for _, gid := range groupIDs {
		gi, err := database.GetGroupInfoByID(db, gid)
		if err != nil {
			continue
		}

		// On construit le DN LDAP complet du groupe
		groupDN := fmt.Sprintf(
			"cn=%s,ou=groups,dc=%s",
			gi.Name,
			strings.ReplaceAll(gi.DomainName, ".", ",dc="),
		)
		logs.Write_Log("DEBUG", "Group DN for user: "+groupDN)
		groupDNs = append(groupDNs, groupDN)
	}

	// Exemple simple d'attributs renvoyés, à adapter selon ta base
	attributes := []PartialAttribute{
		{
			Type: "uid",
			Vals: []string{uid},
		},
		{
			Type: "cn",
			Vals: []string{user.Firstname}, // Récupérer le nom complet de l'utilisateur
		},
		{
			Type: "sn",
			Vals: []string{user.Lastname}, // Récupérer le nom complet de l'utilisateur
		},
		{
			Type: "objectClass",
			Vals: []string{"inetOrgPerson", "posixAccount"},
		},
		{
			Type: "mail",
			Vals: []string{user.Email}, // récupérer depuis ta base
		},
		{
			Type: "whenCreated",
			Vals: []string{createdate}, // Formater la date de création
		},
		{
			Type: "memberOf",
			Vals: groupDNs,
		},
	}

	entry := SearchResultEntry{
		ObjectName: userDN,
		Attributes: attributes,
	}

	err = SendLDAPSearchResultEntry(conn, messageID, entry)
	if err != nil {
		log.Println("Erreur en envoyant l'entrée LDAP :", err)
		return
	}

	SendLDAPSearchResultDone(conn, messageID) // 0 = LDAPResultSuccess
}
