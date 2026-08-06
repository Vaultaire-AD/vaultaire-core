package ldapparser

import (
	"fmt"
	"net"
	"vaultaire/core/database"
	ldaptools "vaultaire/core/ldap/LDAP-TOOLS"
	ldapbindunbind "vaultaire/core/ldap/LDAP_BIND-UNBIND"
	ldapextendedrequest "vaultaire/core/ldap/LDAP_EXTENDED-REQUEST"
	ldapresponse "vaultaire/core/ldap/LDAP_RESPONSE"
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
	// Même règle que partout ailleurs, insensible à la casse et incluant
	// cn=subschema. La comparaison locale d'avant divergeait de celle du
	// résolveur : « cn=subschema » était traité ici comme une base ordinaire
	// — donc refusé avant bind — alors que le résolveur lui rendait le schéma.
	return ldaptools.IsRootDSEBase(searchOp.BaseObject)
}

// supportedControls énumère les contrôles que le serveur sait traiter.
//
// Vide, et le RootDSE l'annonce désormais comme tel. Le jour où la
// pagination sera implémentée, l'OID s'ajoute ici ET dans NewRootDSE — les
// deux listes doivent dire la même chose, c'est tout l'objet de ce refus.
var supportedControls = map[string]bool{}

// rejectUnsupportedCriticalControl applique la RFC 4511 §4.1.11.
//
// Un contrôle marqué CRITIQUE que le serveur ne sait pas traiter doit faire
// échouer l'opération. Un contrôle non critique s'ignore silencieusement,
// c'est précisément ce que veut dire le drapeau.
//
// Avant, tous les contrôles étaient analysés puis ignorés, critiques compris.
// Un client qui paginait recevait donc le jeu complet sans cookie, et
// bouclait sur la même page.
func rejectUnsupportedCriticalControl(message *ldapstorage.LDAPParsedReceivedMessage, messageID int, c net.Conn) bool {
	for _, ctrl := range message.Controls {
		if !ctrl.Criticality || supportedControls[ctrl.ControlType] {
			continue
		}
		logs.Write_Log("WARNING", fmt.Sprintf(
			"ldap: contrôle critique non supporté %q refusé depuis %s",
			ctrl.ControlType, c.RemoteAddr()))
		if err := response.SendUnavailableCriticalExtension(c, messageID, ctrl.ControlType); err != nil {
			logs.Write_Log("ERROR", "ldap: envoi du refus de contrôle critique : "+err.Error())
		}
		return true
	}
	return false
}

func DispatchLDAPOperation(message *ldapstorage.LDAPParsedReceivedMessage, messageID int, c net.Conn) {
	// Avant toute chose : un contrôle critique inconnu interdit l'opération,
	// quelle qu'elle soit.
	if rejectUnsupportedCriticalControl(message, messageID, c) {
		return
	}

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
			response.SendLDAPSearchFailureCode(c, messageID,
				ldapstorage.ResultStrongerAuthRequired, "authentication required")
		default:
			logs.Write_Log("WARNING", fmt.Sprintf("Requête %s refusée : utilisateur non authentifié depuis %s", opType, c.RemoteAddr().String()))
			if err := ldapresponse.SendResult(c, messageID, ldapstorage.AppExtendedResponse,
				ldapstorage.ResultStrongerAuthRequired, "", "authentication required"); err != nil {
				logs.Write_Log("DEBUG", "ldap: "+err.Error())
			}
		}
		return
	}

	// Anonymous bind: RootDSE search and Unbind only
	if session.IsAnonymous {
		if opType == "SearchRequest" && !isRootDSE {
			logs.Write_Log("WARNING", fmt.Sprintf("Accès refusé : utilisateur anonyme tentant une recherche autre que RootDSE depuis %s", c.RemoteAddr().String()))
			response.SendLDAPSearchFailureCode(c, messageID,
				ldapstorage.ResultInsufficientAccessRights, "insufficient access rights")
			return
		}
		if opType != "SearchRequest" && opType != "UnbindRequest" {
			logs.Write_Log("WARNING", fmt.Sprintf("Accès refusé : opération %s interdite pour un anonyme", opType))
			// Répondre, et pas seulement journaliser : sans réponse, le client
			// attend jusqu'à sa propre expiration sans savoir qu'il a été refusé.
			if err := ldapresponse.SendResult(c, messageID, ldapstorage.AppExtendedResponse,
				ldapstorage.ResultInsufficientAccessRights, "", "anonymous access is restricted"); err != nil {
				logs.Write_Log("DEBUG", "ldap: "+err.Error())
			}
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
