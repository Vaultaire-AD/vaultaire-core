package ldapparser

import (
	"fmt"
	"net"
	"vaultaire/core/database"
	ldapbindunbind "vaultaire/core/ldap/LDAP_BIND-UNBIND"
	ldapextendedrequest "vaultaire/core/ldap/LDAP_EXTENDED-REQUEST"
	"vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule"
	"vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/response"
	ldapsessionmanager "vaultaire/core/ldap/LDAP_SESSION-Manager"
	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
	"vaultaire/core/logs"
)

func isRootDSESearch(op ldapstorage.LDAPProtocolOperation) bool {
	searchOp, ok := op.(ldapstorage.SearchRequest)
	if !ok {
		return false
	}
	return searchOp.BaseObject == "" || searchOp.BaseObject == "cn=schema"
}

func DispatchLDAPOperation(message *ldapstorage.LDAPParsedReceivedMessage, messageID int, c net.Conn) {
	opType := message.ProtocolOp.OpType()
	isRootDSE := isRootDSESearch(message.ProtocolOp)

	// Bind always allowed, regardless of session state
	if opType == "BindRequest" {
		if bindOp, ok := message.ProtocolOp.(ldapstorage.BindRequest); ok {
			ldapbindunbind.HandleBindRequest(bindOp, messageID, c)
		}
		return
	}

	session, exists := ldapsessionmanager.GetLDAPSession(c)

	// Pre-bind: only RootDSE search and Unbind are allowed (RFC 4511 client discovery)
	if !exists || !session.IsBound {
		switch {
		case isRootDSE && opType == "SearchRequest":
			if searchOp, ok := message.ProtocolOp.(ldapstorage.SearchRequest); ok {
				newmodule.HandleSearchRequest(database.GetDatabase(), searchOp, messageID, c)
			}
		case opType == "UnbindRequest":
			ldapbindunbind.HandleUnbindRequest(messageID, c)
		case opType == "SearchRequest":
			logs.Write_Log("WARNING", fmt.Sprintf("Requête SearchRequest refusée : utilisateur non authentifié depuis %s", c.RemoteAddr().String()))
			response.SendLDAPSearchFailure(c, messageID, "Authentication required")
		default:
			logs.Write_Log("WARNING", fmt.Sprintf("Requête %s refusée : utilisateur non authentifié depuis %s", opType, c.RemoteAddr().String()))
		}
		return
	}

	// Anonymous bind: RootDSE search and Unbind only
	if session.IsAnonymous {
		if opType == "SearchRequest" && !isRootDSE {
			logs.Write_Log("WARNING", fmt.Sprintf("Accès refusé : utilisateur anonyme tentant une recherche autre que RootDSE depuis %s", c.RemoteAddr().String()))
			response.SendLDAPSearchFailure(c, messageID, "Insufficient Access Rights")
			return
		}
		if opType != "SearchRequest" && opType != "UnbindRequest" {
			logs.Write_Log("WARNING", fmt.Sprintf("Accès refusé : opération %s interdite pour un anonyme", opType))
			return
		}
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
