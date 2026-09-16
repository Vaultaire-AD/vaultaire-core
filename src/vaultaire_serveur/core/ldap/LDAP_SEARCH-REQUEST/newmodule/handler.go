package newmodule

import (
	"database/sql"
	"fmt"
	"net"
	"time"
	ldaptools "vaultaire/core/ldap/LDAP-TOOLS"
	candidate "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate"
	"vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/response"
	scope "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/scope"
	"vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/security"
	ldapsessionmanager "vaultaire/core/ldap/LDAP_SESSION-Manager"
	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
	"vaultaire/core/logs"
)

// HandleSearchRequest traite une requête LDAP Search
func HandleSearchRequest(db *sql.DB, op ldapstorage.SearchRequest, messageID int, conn net.Conn) {
	baseDN := ldaptools.ConvertLDAPBaseToDomainName(op.BaseObject)
	logs.Write_Log("DEBUG", fmt.Sprintf("ldap: search request baseObject=%s baseDomain=%s scope=%d attributes=%v", op.BaseObject, baseDN, op.Scope, op.Attributes))

	// Bases spéciales : RootDSE et sous-schéma. Elles ne désignent aucune entrée
	// de l'annuaire et sont interrogeables sans authentification — c'est ainsi
	// qu'un client découvre ce que le serveur sait faire (RFC 4512).
	//
	// Une seule fonction décide, pour tout le paquet : trois comparaisons
	// divergentes cohabitaient, dont deux sensibles à la casse. « CN=Schema »
	// exigeait un bind mais échappait au contrôle d'autorisation.
	isRootDSE := ldaptools.IsRootDSEBase(op.BaseObject)

	session, ok := ldapsessionmanager.GetLDAPSession(conn)

	// La session peut être ABSENTE, et ce n'est pas théorique : un refus de bind
	// la supprimait autrefois sous une connexion vivante. Lire session.Username
	// dans ce cas déréférençait un pointeur nil et arrêtait le serveur entier.
	//
	// On travaille donc sur une valeur locale, jamais sur le pointeur.
	username := ""
	isBound := false
	if ok && session != nil {
		username = session.Username
		isBound = session.IsBound
	}

	if !isRootDSE {
		if !isBound {
			response.SendLDAPSearchFailureCode(conn, messageID,
				ldapstorage.ResultStrongerAuthRequired, "authentication required")
			return
		}
		if !security.IsAuthorizedToSearch(username, baseDN) {
			response.SendLDAPSearchFailureCode(conn, messageID,
				ldapstorage.ResultInsufficientAccessRights, "insufficient access rights")
			return
		}
	}

	// 1. Résoudre le scope → candidats
	candidates, err := scope.Resolve(db, baseDN, op.Scope, op.Attributes, username, op.BaseObject)
	if err != nil {
		response.SendLDAPSearchFailure(conn, messageID, err.Error())
		return
	}
	logs.Write_Log("DEBUG", fmt.Sprintf("ldap: resolved %d candidates for baseDN=%s scope=%d", len(candidates), baseDN, op.Scope))
	// for _, candidate := range candidates {
	// 	scope.PrintLDAPEntry(candidate)
	// }
	if len(candidates) == 0 {
		logs.Write_Log("DEBUG", "ldap: aucun candidat resolu, envoi direct de SearchResultDone")
		response.SendLDAPSearchResultDone(conn, messageID)
		return
	}

	// 2. Évaluer le filtre
	matched := candidate.Filtre(candidates, op.Filter, baseDN, op.Scope)

	// 3. Construire et envoyer les réponses, dans les limites.
	//
	// sizeLimit et timeLimit étaient décodés puis IGNORÉS. Un client qui demandait
	// une entrée recevait l'annuaire entier — et rien n'empêchait de le demander
	// en boucle.
	limite := effectiveSizeLimit(op.SizeLimit)
	délai := effectiveTimeLimit(op.TimeLimit)
	début := time.Now()

	envoyées := 0
	for _, entry := range matched {
		if limite > 0 && envoyées >= limite {
			logs.Write_Log("DEBUG", fmt.Sprintf(
				"ldap: recherche tronquée à %d entrées (demandé %d, borne serveur %d)",
				envoyées, op.SizeLimit, ldapstorage.MaxSearchEntries))
			response.SendLDAPSearchFailureCode(conn, messageID,
				ldapstorage.ResultSizeLimitExceeded, "size limit exceeded")
			return
		}
		if délai > 0 && time.Since(début) > délai {
			logs.Write_Log("WARNING", fmt.Sprintf(
				"ldap: recherche interrompue après %s sur baseDN=%s", délai, baseDN))
			response.SendLDAPSearchFailureCode(conn, messageID,
				ldapstorage.ResultTimeLimitExceeded, "time limit exceeded")
			return
		}

		resp := response.BuildLDAPEntryForSend(entry, op.Attributes, op.TypesOnly)
		if err := response.SendLDAPSearchResultEntry(conn, messageID, resp); err != nil {
			// L'écriture a échoué : le client est probablement parti. Insister sur
			// les entrées suivantes ne ferait qu'occuper une goroutine à écrire
			// dans le vide.
			logs.Write_Log("WARNING", err.Error())
			return
		}
		envoyées++
	}

	response.SendLDAPSearchResultDone(conn, messageID)
}

// effectiveSizeLimit combine la demande du client et la borne du serveur.
//
// Le client envoie 0 pour « sans limite » — ce que fait aussi tout client
// hostile. La borne serveur est donc la seule qui tienne face à quelqu'un qui ne
// coopère pas ; celle du client ne peut que la réduire.
func effectiveSizeLimit(demandé int) int {
	borne := ldapstorage.MaxSearchEntries
	if demandé > 0 && (borne <= 0 || demandé < borne) {
		return demandé
	}
	return borne
}

// effectiveTimeLimit combine de la même façon les deux délais.
func effectiveTimeLimit(demandéSecondes int) time.Duration {
	borne := time.Duration(ldapstorage.MaxSearchDurationSeconds) * time.Second
	if demandéSecondes > 0 {
		demandé := time.Duration(demandéSecondes) * time.Second
		if borne <= 0 || demandé < borne {
			return demandé
		}
	}
	return borne
}
