package ldapparser

import (
	"vaultaire/serveur/database"
	ldapbindunbind "vaultaire/serveur/ldap/LDAP_BIND-UNBIND"
	ldapextendedrequest "vaultaire/serveur/ldap/LDAP_EXTENDED-REQUEST"
	"vaultaire/serveur/ldap/LDAP_SEARCH-REQUEST/newmodule"
	ldapsessionmanager "vaultaire/serveur/ldap/LDAP_SESSION-Manager"
	ldapstorage "vaultaire/serveur/ldap/LDAP_Storage"
	"vaultaire/serveur/logs"
	"fmt"
	"net"
)

func DispatchLDAPOperation(message *ldapstorage.LDAPParsedReceivedMessage, messageID int, c net.Conn) {
	opType := message.ProtocolOp.OpType()
	session, _ := ldapsessionmanager.GetLDAPSession(c)

	// Si la requête n’est PAS un BindRequest et que la session n’est pas encore authentifiée
	if opType != "BindRequest" && (session == nil || !session.IsBound) {
		logs.Write_Log("WARNING", fmt.Sprintf("Requête %s refusée : utilisateur non authentifié Depuis : %s", opType, c.RemoteAddr().String()))
		ldapsessionmanager.ClearSession(c)
		return
	}

	switch op := message.ProtocolOp.(type) {
	case ldapstorage.BindRequest:
		ldapbindunbind.HandleBindRequest(op, messageID, c)
	case ldapstorage.UnbindRequest:
		ldapbindunbind.HandleUnbindRequest(messageID, c)
	case ldapstorage.ExtendedRequest:
		ldapextendedrequest.HandleExtendedRequest(op, messageID, c)
	case ldapstorage.SearchRequest:
		newmodule.HandleSearchRequest(database.GetDatabase(), op, messageID, c)
		//ldapsearch.HandleSearchRequest(op, messageID, c)
	// case "ExtendedRequest":
	// 	handleExtendedRequest(message)
	default:
		logs.Write_Log("WARNING", fmt.Sprintf("Requête non supportée : %s depuis %s", opType, c.RemoteAddr().String()))
	}
}
