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
	"vaultaire/core/storage"
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

	// La portée du compte : les domaines qu'il a le droit de lire.
	//
	// Lue UNE fois ici, puis consultée pour chaque entrée. Elle sert donc deux
	// fois : à refuser la recherche d'emblée quand le baseDN n'est pas autorisé,
	// et à écarter les entrées que le résolveur ramène hors de cette portée —
	// voir security.PorteeDeRecherche pour ce que cela ferme.
	var portée *security.PorteeDeRecherche

	if !isRootDSE {
		if !isBound {
			response.SendLDAPSearchFailureCode(conn, messageID,
				ldapstorage.ResultStrongerAuthRequired, "authentication required")
			return
		}

		var err error
		portée, err = security.PorteeDeRecherchePour(username)
		if err != nil {
			// Une lecture de droits qui échoue REFUSE. Le message reste celui des
			// droits insuffisants : dire au client que la base est en difficulté ne
			// l'aide pas et renseigne qui sonde la porte. Le journal, lui, distingue.
			logs.Write_LogCode("ERROR", logs.CodeAuthPermission, fmt.Sprintf(
				"ldap: droits de recherche illisibles pour %s (%v) — refusé", username, err))
			response.SendLDAPSearchFailureCode(conn, messageID,
				ldapstorage.ResultInsufficientAccessRights, "insufficient access rights")
			return
		}

		if !portée.Autorise(baseDN) {
			// Un baseObject dont on ne tire AUCUN domaine tombe ici, et ce n'est pas
			// un refus de droits : c'est une base que le serveur ne sait pas situer,
			// et qui n'est ni le RootDSE ni le sous-schéma. Le dire dans le journal,
			// sans quoi l'administrateur cherchera une permission manquante.
			//
			// La réponse, elle, reste `insufficientAccessRights` : le code juste
			// serait `noSuchObject` (32), qui n'est pas encore rendu — voir le
			// point 124.
			if baseDN == "" {
				logs.Write_Log("WARNING", fmt.Sprintf(
					"ldap: baseObject %q sans composant dc= — aucun domaine à autoriser",
					op.BaseObject))
			}
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

	// LE FILTRE D'AUTORISATION, avant le filtre LDAP.
	//
	// `Resolve` charge le domaine demandé ET ses sous-domaines : c'est voulu pour
	// une recherche subtree, et c'était jusqu'ici sans aucun contrôle. Un compte
	// autorisé sur `enov.local` sans propagation recevait `admin.enov.local`.
	//
	// Placé ICI, et pas dans la boucle d'envoi, pour deux raisons : le filtre LDAP
	// n'a pas à voir des entrées que le compte n'a pas le droit de lire, et la
	// borne `sizeLimit` doit compter ce qui est rendu, pas ce qui a été écarté.
	//
	// Le RootDSE et le sous-schéma passent à côté : ils n'appartiennent à aucun
	// domaine et sont servis sans authentification (RFC 4512).
	//
	// La condition est `!isRootDSE`, la MÊME que celle qui a accordé la dispense
	// plus haut — et non « si une portée a été lue ». La différence compte : si un
	// chemin futur arrivait ici sans portée, `Filtrer` écarterait tout, ce qui se
	// voit immédiatement. Tester le pointeur aurait, dans ce même cas, tout laissé
	// passer.
	if !isRootDSE {
		retenues, écartées := portée.Filtrer(candidates)
		if écartées > 0 {
			logs.Write_Log("DEBUG", fmt.Sprintf(
				"ldap: %d entrée(s) écartée(s) des droits de %s sur baseDN=%s, %d rendue(s)",
				écartées, username, baseDN, len(retenues)))
		}
		candidates = retenues
	}

	// Le vidage détaillé, APRÈS le filtre.
	//
	// Il avait lieu dans le résolveur, donc avant : le journal DEBUG portait le
	// contenu des entrées que le compte n'a pas le droit de lire. Corriger la
	// fuite vers le client en la laissant vers le journal n'aurait rien corrigé.
	if storage.Debug {
		for _, e := range candidates {
			logs.Write_Log("DEBUG", scope.DumpLDAPEntry(e, op.Attributes))
		}
	}
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

	avecDroits := droitsServiceDemandes(op.Attributes)

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

		// Droits de service : calculés entrée par entrée, et seulement si
		// demandés. Voir service_rights.go.
		if ue, ok := entry.(candidate.UserEntry); ok && avecDroits {
			ue.ServiceRights = droitsService(username, ue)
			entry = ue
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
