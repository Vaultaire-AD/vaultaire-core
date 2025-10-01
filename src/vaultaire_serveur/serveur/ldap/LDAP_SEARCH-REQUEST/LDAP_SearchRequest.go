package ldapsearchrequest

import (
	"DUCKY/serveur/database"
	"DUCKY/serveur/database/db_permission"
	ldaptools "DUCKY/serveur/ldap/LDAP-TOOLS"
	ldapsessionmanager "DUCKY/serveur/ldap/LDAP_SESSION-Manager"
	ldapstorage "DUCKY/serveur/ldap/LDAP_Storage"
	"DUCKY/serveur/logs"
	"DUCKY/serveur/permission"
	"DUCKY/serveur/storage"
	"fmt"
	"log"
	"net"
)

func HandleSearchRequest(op ldapstorage.SearchRequest, messageID int, conn net.Conn) {
	session, ok := ldapsessionmanager.GetLDAPSession(conn)
	if !ok || !session.IsBound {
		fmt.Println("Session invalide ou non authentifiée.")

		return
	}
	if storage.Ldap_Debug {

		fmt.Println("Handling Search Request")
		fmt.Printf("BaseObject   : %s\n", op.BaseObject)
		op.BaseObject = ldaptools.ConvertLDAPBaseToDomainName(op.BaseObject)
		fmt.Printf("BaseDomain   : %s\n", op.BaseObject)
		fmt.Printf("Scope        : %d\n", op.Scope)
		fmt.Printf("DerefAliases : %d\n", op.DerefAliases)
		fmt.Printf("SizeLimit    : %d\n", op.SizeLimit)
		fmt.Printf("TimeLimit    : %d\n", op.TimeLimit)
		fmt.Printf("TypesOnly    : %v\n", op.TypesOnly)
		fmt.Printf("Attributes   : %v\n", op.Attributes)
	}
	// Vérifier les permissions en base de données
	rawPerms, err := db_permission.GetUserPermissionsForAction(database.GetDatabase(), session.Username, "search")
	if err != nil {
		logs.Write_Log("ERROR", "Erreur lors de la récupération des permissions utilisateur : "+err.Error())
		err := SendLDAPSearchFailure(conn, messageID, "erreur au niveau du user source de l'aplpicatif contact your administrator.")
		if err != nil {
			logs.Write_Log("ERROR", "Error sending LDAP search failure: "+err.Error())
		}
		return
	}
	if !permission.IsUserAuthorizedToSearch(rawPerms, op.BaseObject) {
		logs.Write_Log("WARNING", fmt.Sprintf("Utilisateur %s n'est pas autorisé à faire une recherche sur %s", session.Username, op.BaseObject))
		err := SendLDAPSearchFailure(conn, messageID, "erreur au niveau du user source de l'aplpicatif contact your administrator.")
		if err != nil {
			logs.Write_Log("ERROR", "Error sending LDAP search failure: "+err.Error())
		}
		return
	}
	filters, err := ExtractEqualityFilters(op.Filter)
	fmt.Println("Filter :")
	for _, filtre := range filters {
		fmt.Println(filtre.Attribute + " : " + filtre.Value)
	}
	if err != nil {
		fmt.Println("Erreur lors du parsing du filtre :", err)
		return
	} else {
		keywordMap := map[string][]string{
			"user":  {"user", "person", "inetorgperson", "posixaccount"},
			"group": {"group", "groupofnames", "groupofuniquenames"},
		}

		foundCategories := ldaptools.DetectKeywordCategories(filters, keywordMap)

		if foundCategories["user"] {
			fmt.Println("→ Déclenchement du traitement pour les **utilisateurs**")
			SearchUserRequest(conn, messageID, op.BaseObject, op.Attributes, filters)
			return
		}
		if foundCategories["group"] {
			fmt.Println("→ Déclenchement du traitement pour les **groupes**")
			SearchGroupRequest(conn, messageID, database.GetDatabase(), op.BaseObject, filters, op.BaseObject)
			return
		}
		if foundCategories["uid"] {
			fmt.Println("→ Déclenchement du traitement pour les **uid**")
			// ici c'est pour les recherche sur 1 user precies
			domain, err := database.FindUserDomainFromGroups(filters[0].Value, op.BaseObject, database.GetDatabase())
			if err != nil {
				logs.Write_Log("ERROR", "Erreur lors de la recherche du domaine pour l'utilisateur "+filters[0].Value+": "+err.Error())
				err := SendLDAPSearchFailure(conn, messageID, "Aucun domaine trouvé sous la forêt pour l'utilisateur")
				if err != nil {
					logs.Write_Log("ERROR", "Error sending LDAP search failure: "+err.Error())
				}
				return
			}
			uid := filters[0].Value
			SendUidSearchRequest(uid, domain, conn, messageID)
			return
		}
		if foundCategories["member"] {
			fmt.Println("→ Déclenchement du traitement pour les **membres du pipi**")
			dn := filters[0].Value                              // "uid=fiona,dc=it,dc=company,dc=com"
			uid, _, _ := ldaptools.ExtractUsernameAndDomain(dn) // => "fiona"
			groups, err := database.FindGroupsByUserInDomainTree(database.GetDatabase(), uid, op.BaseObject)
			if err != nil {
				log.Println("Erreur récupération groupes :", err)
				err := SendLDAPSearchFailure(conn, messageID, "Erreur interne")
				if err != nil {
					logs.Write_Log("ERROR", "Error sending LDAP search failure: "+err.Error())
				}
				return
			}
			for _, group := range groups {
				if storage.Ldap_Debug {
					fmt.Println("Group found for member:", group)
				}
				entry := SearchResultEntry{
					ObjectName: fmt.Sprintf("cn=%s,"+op.BaseObject, group),
					Attributes: []PartialAttribute{
						{Type: "objectClass", Vals: []string{"groupOfNames"}},
						{Type: "cn", Vals: []string{group}},
						{Type: "member", Vals: []string{"uid=eric,dc=infra,dc=it,dc=company,dc=com"}},
						// {Type: "dn", Vals: []string{dn}},
					},
				}
				err := SendLDAPSearchResultEntry(conn, messageID, entry)
				if err != nil {
					logs.Write_Log("ERROR", "Error sending LDAP search result entry: "+err.Error())
					return
				}
			}
			SendLDAPSearchResultDone(conn, messageID)
			return
		}
		if len(foundCategories) == 0 {
			fmt.Println("Aucune entité correspondante détectée dans les filtres.")
			err := SendLDAPSearchFailure(conn, messageID, "Aucune entité correspondante détectée dans les filtres.")
			if err != nil {
				logs.Write_Log("ERROR", "Error sending LDAP search failure: "+err.Error())
			}
			return
		}
	}
}
