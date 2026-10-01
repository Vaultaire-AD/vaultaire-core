package newmodule

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"time"
	ldaptools "vaultaire/core/ldap/LDAP-TOOLS"
	candidate "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate"
	"vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/filter"
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
			// La réponse, elle, reste `insufficientAccessRights` et non
			// `noSuchObject` : le refus est prononcé AVANT qu'on sache si quoi que
			// ce soit existe, et l'appelant connaît déjà sa propre absence de droits
			// sur ce qu'il a demandé.
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

	// LE FILTRE EST VÉRIFIÉ AVANT D'ÊTRE APPLIQUÉ.
	//
	// Une seule fois par recherche, et non par entrée : le motif ne dépend pas de
	// l'entrée, et le journaliser des milliers de fois noierait le journal.
	//
	// Ce qui n'est pas géré est REFUSÉ, avec le code qui convient. Auparavant, un
	// filtre non géré faisait échouer toutes les entrées en silence : le client
	// recevait « success » et zéro entrée, et croyait sa question posée.
	if err := filter.Verifier(op.Filter); err != nil {
		code := ldapstorage.ResultInappropriateMatching
		var ef *filter.ErreurFiltre
		if errors.As(err, &ef) {
			code = ef.Code
		}
		// WARNING pour une session LIÉE, DEBUG sinon.
		//
		// Ce chemin s'exécute aussi sur une recherche RootDSE, c'est-à-dire avant
		// toute authentification : un inconnu qui envoie des filtres malformés en
		// boucle écrirait une ligne d'avertissement par paquet. La règle « une fois
		// par recherche et non par entrée » ne protège de rien quand c'est
		// l'attaquant qui choisit le nombre de recherches.
		niveau := "DEBUG"
		if isBound {
			niveau = "WARNING"
		}
		logs.Write_Log(niveau, fmt.Sprintf(
			"ldap: filtre refusé pour %s sur baseDN=%s : %s", username, baseDN, err.Error()))
		response.SendLDAPSearchFailureCode(conn, messageID, code, err.Error())
		return
	}

	// LA BASE EXISTE-T-ELLE.
	//
	// Vérifié AVANT de résoudre, pour deux raisons. La première est le point 124 :
	// un baseObject qui ne désigne rien doit rendre `noSuchObject` (32), et non un
	// succès sans entrée. La seconde est que le résolveur fabriquait des unités
	// d'organisation `users` et `groups` pour n'importe quel domaine, existant ou
	// non — une recherche sur un domaine inventé rendait donc deux entrées
	// inventées.
	ancetre := ""
	if !isRootDSE {
		var baseValide bool
		ancetre, baseValide = scope.AncetreExistant(db, op.BaseObject)
		if !baseValide {
			logs.Write_Log("DEBUG", fmt.Sprintf(
				"ldap: baseObject %q inexistant, matchedDN=%q", op.BaseObject, ancetre))
			response.SendLDAPNoSuchObject(conn, messageID, ancetre)
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
	// AUCUN CANDIDAT : la base est structurellement valide, mais rien n'en sort.
	//
	// C'est `noSuchObject`, et la MÊME réponse que la feuille soit absente ou
	// qu'elle existe sans que l'appelant ait le droit de la voir. C'est
	// délibéré : distinguer les deux ferait de cette réponse un ORACLE — il
	// suffirait de comparer 32 et « succès sans entrée » pour savoir si un compte
	// existe dans un domaine qu'on n'a pas le droit de lire.
	//
	// Une recherche `one` ou `sub` sur un domaine existant rend toujours ses deux
	// unités d'organisation : ce cas ne concerne donc en pratique que les
	// recherches `base`, ce qui est exactement là où un client pose la question
	// « ce DN existe-t-il ».
	if len(candidates) == 0 {
		logs.Write_Log("DEBUG", fmt.Sprintf(
			"ldap: %q ne rend aucune entrée (absente ou hors droits), matchedDN=%q",
			op.BaseObject, ancetre))
		response.SendLDAPNoSuchObject(conn, messageID, ancetre)
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
