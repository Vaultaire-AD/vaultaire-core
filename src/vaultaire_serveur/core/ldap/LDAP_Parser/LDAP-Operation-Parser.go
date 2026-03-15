package ldapparser

import (
	"fmt"
	"net"
	"vaultaire/core/database"
	ldapbindunbind "vaultaire/core/ldap/LDAP_BIND-UNBIND"
	ldapextendedrequest "vaultaire/core/ldap/LDAP_EXTENDED-REQUEST"
	"vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule"
	ldapsessionmanager "vaultaire/core/ldap/LDAP_SESSION-Manager"
	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
	"vaultaire/core/logs"
)

func DispatchLDAPOperation(message *ldapstorage.LDAPParsedReceivedMessage, messageID int, c net.Conn) {
	opType := message.ProtocolOp.OpType()

	// 1. LE BIND EST SACRÉ : Il doit toujours passer, peu importe l'état de la session
	if opType == "BindRequest" {
		if bindOp, ok := message.ProtocolOp.(ldapstorage.BindRequest); ok {
			ldapbindunbind.HandleBindRequest(bindOp, messageID, c)
			return
		}
	}
	// 2. Maintenant, on récupère la session pour les autres opérations
	session, exists := ldapsessionmanager.GetLDAPSession(c)
	if !exists || !session.IsBound {
		// Bloquer tout sauf si c'est une requête RootDSE (si vous autorisez l'anonyme "pré-bind")
		// ... (votre logique actuelle) ...
		return
	}

	// 1. Déterminer si c'est une recherche RootDSE
	isRootDSE := false
	if searchOp, ok := message.ProtocolOp.(ldapstorage.SearchRequest); ok {
		if searchOp.BaseObject == "" || searchOp.BaseObject == "cn=schema" {
			isRootDSE = true
		}
	}
	// 2. Vérification de sécurité pour les utilisateurs anonymes
	if session != nil && session.IsBound && session.IsAnonymous {
		// Si l'utilisateur est anonyme, il NE DOIT PAS faire autre chose que le RootDSE
		// (Le RootDSE est déjà autorisé par la condition isRootDSE)
		if opType == "SearchRequest" && !isRootDSE {
			logs.Write_Log("WARNING", fmt.Sprintf("Accès refusé : utilisateur anonyme tentant une recherche autre que RootDSE depuis %s", c.RemoteAddr().String()))
			// Envoyer une erreur LDAP "Insufficient Access Rights" (code 50)
			// response.SendLDAPResult(c, messageID, 50, "Insufficient Access Rights")
			return
		}

		// Bloquer tout autre type d'opération sensible pour un anonyme
		if opType != "SearchRequest" && opType != "UnbindRequest" {
			logs.Write_Log("WARNING", fmt.Sprintf("Accès refusé : opération %s interdite pour un anonyme", opType))
			return
		}
	}

	// // Si la requête n’est PAS un BindRequest et que la session n’est pas encore authentifiée
	// if opType != "BindRequest" && (session == nil || !session.IsBound) {
	// 	logs.Write_Log("WARNING", fmt.Sprintf("Requête %s refusée : utilisateur non authentifié Depuis : %s", opType, c.RemoteAddr().String()))
	// 	ldapsessionmanager.ClearSession(c)
	// 	return
	// }
	// Si ce n'est PAS un BindRequest ET PAS une recherche RootDSE ET pas authentifié -> REFUSER
	if opType != "BindRequest" && !isRootDSE && (session == nil || !session.IsBound) {
		logs.Write_Log("WARNING", fmt.Sprintf("Requête %s refusée : utilisateur non authentifié", opType))
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
