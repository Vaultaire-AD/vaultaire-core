package ldapparser

import (
	"fmt"
	"net"
	"vaultaire/core/database"
	ldaptools "vaultaire/core/ldap/LDAP-TOOLS"
	ldapbindunbind "vaultaire/core/ldap/LDAP_BIND-UNBIND"
	ldapextendedrequest "vaultaire/core/ldap/LDAP_EXTENDED-REQUEST"
	ldapjournal "vaultaire/core/ldap/LDAP_Journal"
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

// controleAdmis dit si un contrôle est traité POUR CETTE OPÉRATION.
//
// La liste est ldapstorage.ControlesGeres, la même que celle que le RootDSE
// annonce : les deux ne peuvent plus se contredire.
//
// « Pour cette opération », parce qu'un contrôle n'a de sens que là où il
// s'applique (RFC 4511 §4.1.11). La pagination ne s'applique qu'à une
// recherche : marquée critique sur un bind, elle doit le faire échouer, comme
// tout contrôle critique que le serveur ne sait pas honorer là.
func controleAdmis(controlType, opType string) bool {
	for _, oid := range ldapstorage.ControlesGeres {
		if oid != controlType {
			continue
		}
		switch oid {
		case ldapstorage.OIDPagedResults:
			return opType == "SearchRequest"
		}
	}
	return false
}

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
	opType := message.ProtocolOp.OpType()
	for _, ctrl := range message.Controls {
		if !ctrl.Criticality || controleAdmis(ctrl.ControlType, opType) {
			continue
		}
		ldapjournal.Ecrire(c, "WARNING", logs.CodeNone, fmt.Sprintf(
			"contrôle critique non supporté %q refusé depuis %s",
			ctrl.ControlType, c.RemoteAddr()))
		if err := response.SendUnavailableCriticalExtension(c, messageID, ctrl.ControlType); err != nil {
			ldapjournal.Ecrire(c, "ERROR", logs.CodeNone, "envoi du refus de contrôle critique : "+err.Error())
		}
		return true
	}
	return false
}

// avecPagination range le contrôle de pagination dans la recherche.
//
// Fait ICI, à l'entrée, pour que le gestionnaire de recherche n'ait jamais à
// connaître les contrôles du message : il reçoit une recherche, paginée ou non.
//
// Un contrôle malformé est une erreur de PROTOCOLE, même non critique : le
// client a demandé quelque chose qu'on ne sait pas lire, et lui servir la
// recherche entière à la place serait deviner. Le booléen rendu dit si la
// recherche peut continuer.
func avecPagination(message *ldapstorage.LDAPParsedReceivedMessage, messageID int, c net.Conn) bool {
	recherche, ok := message.ProtocolOp.(ldapstorage.SearchRequest)
	if !ok {
		return true
	}
	page, err := extrairePagination(message.Controls)
	if err != nil {
		ldapjournal.Ecrire(c, "WARNING", logs.CodeNone, fmt.Sprintf("%s, depuis %s", err.Error(), c.RemoteAddr()))
		response.SendLDAPSearchFailureCode(c, messageID, ldapstorage.ResultProtocolError,
			"malformed paged results control")
		return false
	}
	recherche.Page = page
	message.ProtocolOp = recherche
	return true
}

func DispatchLDAPOperation(message *ldapstorage.LDAPParsedReceivedMessage, messageID int, c net.Conn) {
	// Avant toute chose : un contrôle critique inconnu interdit l'opération,
	// quelle qu'elle soit.
	if rejectUnsupportedCriticalControl(message, messageID, c) {
		return
	}
	if !avecPagination(message, messageID, c) {
		return
	}
	// La pagination vient d'être rangée dans la recherche : la ligne de
	// l'opération la dira (« page=500 », « (suite) »).
	ldapjournal.EnCours(c).Redire(ldapjournal.Decrire(message.ProtocolOp, message.Controls))

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
			ldapjournal.Ecrire(c, "WARNING", logs.CodeNone, fmt.Sprintf("requête SearchRequest refusée : utilisateur non authentifié depuis %s", c.RemoteAddr().String()))
			response.SendLDAPSearchFailureCode(c, messageID,
				ldapstorage.ResultStrongerAuthRequired, "authentication required")
		default:
			ldapjournal.Ecrire(c, "WARNING", logs.CodeNone, fmt.Sprintf("requête %s refusée : utilisateur non authentifié depuis %s", opType, c.RemoteAddr().String()))
			if err := ldapresponse.SendResult(c, messageID, ldapstorage.AppExtendedResponse,
				ldapstorage.ResultStrongerAuthRequired, "", "authentication required"); err != nil {
				ldapjournal.Trace(c, "%v", err)
			}
		}
		return
	}

	// Anonymous bind: RootDSE search and Unbind only
	if session.IsAnonymous {
		if opType == "SearchRequest" && !isRootDSE {
			ldapjournal.Ecrire(c, "WARNING", logs.CodeNone, fmt.Sprintf("accès refusé : utilisateur anonyme tentant une recherche autre que RootDSE depuis %s", c.RemoteAddr().String()))
			response.SendLDAPSearchFailureCode(c, messageID,
				ldapstorage.ResultInsufficientAccessRights, "insufficient access rights")
			return
		}
		if opType != "SearchRequest" && opType != "UnbindRequest" {
			ldapjournal.Ecrire(c, "WARNING", logs.CodeNone, fmt.Sprintf("accès refusé : opération %s interdite pour un anonyme", opType))
			// Répondre, et pas seulement journaliser : sans réponse, le client
			// attend jusqu'à sa propre expiration sans savoir qu'il a été refusé.
			if err := ldapresponse.SendResult(c, messageID, ldapstorage.AppExtendedResponse,
				ldapstorage.ResultInsufficientAccessRights, "", "anonymous access is restricted"); err != nil {
				ldapjournal.Trace(c, "%v", err)
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
		ldapjournal.Ecrire(c, "WARNING", logs.CodeNone, fmt.Sprintf("requête non supportée : %s depuis %s", opType, c.RemoteAddr().String()))
	}
}
