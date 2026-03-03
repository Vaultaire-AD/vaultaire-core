package newmodule

import (
	ldaptools "vaultaire/serveur/ldap/LDAP-TOOLS"
	candidate "vaultaire/serveur/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate"
	"vaultaire/serveur/ldap/LDAP_SEARCH-REQUEST/newmodule/response"
	scope "vaultaire/serveur/ldap/LDAP_SEARCH-REQUEST/newmodule/scope"
	"vaultaire/serveur/ldap/LDAP_SEARCH-REQUEST/newmodule/security"
	ldapsessionmanager "vaultaire/serveur/ldap/LDAP_SESSION-Manager"
	ldapstorage "vaultaire/serveur/ldap/LDAP_Storage"
	"vaultaire/serveur/logs"
	"database/sql"
	"fmt"
	"net"
)

// HandleSearchRequest traite une requête LDAP Search
func HandleSearchRequest(db *sql.DB, op ldapstorage.SearchRequest, messageID int, conn net.Conn) {
	baseDN := ldaptools.ConvertLDAPBaseToDomainName(op.BaseObject)
	logs.Write_Log("DEBUG", fmt.Sprintf("ldap: search request baseObject=%s baseDomain=%s scope=%d attributes=%v", op.BaseObject, baseDN, op.Scope, op.Attributes))
	if len(op.Attributes) == 0 {
		op.Attributes = []string{"dn"}
	}

	session, ok := ldapsessionmanager.GetLDAPSession(conn)
	if !ok || !session.IsBound {
		response.SendLDAPSearchFailure(conn, messageID, "Session invalide ou non bindée")
		return
	}

	if baseDN == "" && op.Filter.Type == ldapstorage.FilterPresent && op.Filter.Attribute == "objectClass" {
		scope.HandleGlobalUserDisplayNameSearch(conn, messageID, session, db, op.Attributes)
		return
	}
	// Root DSE
	if baseDN == "" {
		SendRootDSE(conn, messageID)
		return
	}

	if !security.IsAuthorizedToSearch(session.Username, baseDN) {
		response.SendLDAPSearchFailure(conn, messageID, "Not authorized")
		return
	}

	// 1. Résoudre le scope → candidats
	candidates, err := scope.Resolve(db, baseDN, op.Scope, op.Attributes, session.Username)
	if err != nil {
		response.SendLDAPSearchFailure(conn, messageID, err.Error())
		return
	}

	fmt.Printf("Resolved %d candidates for BaseDN '%s' with scope %d\n", len(candidates), baseDN, op.Scope)
	// for _, candidate := range candidates {
	// 	scope.PrintLDAPEntry(candidate)
	// }
	// 2. Évaluer le filtre
	matched := candidate.Filtre(candidates, op.Filter)

	// 3. Construire et envoyer les réponses
	for _, entry := range matched {
		resp := response.BuildLDAPEntryForSend(entry, op.Attributes)
		err := response.SendLDAPSearchResultEntry(conn, messageID, resp)
		if err != nil {
			// log l'erreur mais on continue
			logs.Write_Log("WARNING", err.Error())
			continue
		}
	}

	response.SendLDAPSearchResultDone(conn, messageID)
}
