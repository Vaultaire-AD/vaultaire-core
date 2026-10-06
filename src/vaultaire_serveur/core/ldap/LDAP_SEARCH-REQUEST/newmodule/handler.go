package newmodule

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"time"
	ldaptools "vaultaire/core/ldap/LDAP-TOOLS"
	ldapjournal "vaultaire/core/ldap/LDAP_Journal"
	candidate "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate"
	ldapinterface "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate/ldap_interface"
	"vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/filter"
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

	// Le journal de l'opération (TO-DO 145). La demande — base, portée, filtre,
	// attributs — y est déjà : elle a été écrite par la boucle de lecture, et
	// sortira sur UNE ligne avec le résultat, quand la recherche sera finie. Ce
	// gestionnaire n'y ajoute que ce qui explique le résultat : combien de
	// candidats, combien écartés par les droits. Le reste est du déroulé, en
	// TRACE. `j` vaut nil hors d'une connexion suivie ; ses méthodes l'acceptent.
	j := ldapjournal.EnCours(conn)

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
			ldapjournal.Ecrire(conn, "ERROR", logs.CodeAuthPermission, fmt.Sprintf(
				"droits de recherche illisibles pour %s (%v) — refusé", username, err))
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
				ldapjournal.Ecrire(conn, "WARNING", logs.CodeNone, fmt.Sprintf(
					"baseObject %q sans composant dc= — aucun domaine à autoriser",
					op.BaseObject))
			}
			response.SendLDAPSearchFailureCode(conn, messageID,
				ldapstorage.ResultInsufficientAccessRights, "insufficient access rights")
			return
		}
	}

	// LA SUITE D'UNE RECHERCHE PAGINÉE — point 130.
	//
	// Une requête qui porte un cookie ne lance PAS de recherche : elle réclame la
	// page suivante d'un jeu figé à la première requête. Rien n'est donc résolu
	// ni filtré ici.
	//
	// Placée APRÈS le contrôle des droits, et c'est voulu : la session doit
	// toujours être liée, et le compte toujours autorisé sur cette base. Le jeu a
	// été calculé avec les droits de la première requête ; les relire à chaque
	// page coûte une lecture, et ferme la fenêtre pendant laquelle un compte dont
	// on vient de retirer les droits continuerait de lire la suite.
	if op.Page != nil && len(op.Page.Cookie) > 0 {
		servirPageSuivante(conn, messageID, op, username, baseDN)
		return
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
		// WARNING pour une session LIÉE seulement.
		//
		// Ce chemin s'exécute aussi sur une recherche RootDSE, c'est-à-dire avant
		// toute authentification : un inconnu qui envoie des filtres malformés en
		// boucle écrirait une ligne d'avertissement par paquet. La règle « une fois
		// par recherche et non par entrée » ne protège de rien quand c'est
		// l'attaquant qui choisit le nombre de recherches.
		//
		// Pour une session non liée, le refus se lit sur la ligne de l'opération —
		// le filtre et le code de résultat y sont — et le motif en déroulé.
		if isBound {
			ldapjournal.Ecrire(conn, "WARNING", logs.CodeNone, fmt.Sprintf(
				"filtre refusé pour %s sur baseDN=%s : %s", username, baseDN, err.Error()))
		} else {
			j.Trace("filtre refusé : %s", err.Error())
		}
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
			j.Noter("matchedDN", fmt.Sprintf("%q", ancetre))
			response.SendLDAPNoSuchObject(conn, messageID, ancetre)
			return
		}
	}

	// 1. Résoudre le scope → candidats
	candidates, err := scope.Resolve(db, baseDN, op.Scope, op.Attributes, username, op.BaseObject, j)
	if err != nil {
		// La cause part au journal : le client ne reçoit qu'un
		// `operationsError`, et sans cette ligne rien ne disait, côté serveur,
		// qu'une recherche venait d'échouer sur une lecture de la base.
		ldapjournal.Ecrire(conn, "ERROR", logs.CodeDBQuery, "résolution de la recherche : "+err.Error())
		response.SendLDAPSearchFailure(conn, messageID, err.Error())
		return
	}
	j.Noter("candidats", len(candidates))

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
		// `Filtrer` fait deux choses d'un seul passage : il écarte les entrées
		// hors des droits du compte, et rend les autres RESTREINTES — privées de
		// ce que leurs attributs nomment et que le compte ne peut pas lire
		// (TO-DO 132 : `memberOf` portait les groupes des sous-domaines).
		retenues, écartées := portée.Filtrer(candidates)
		if écartées > 0 {
			// Sur la ligne de l'opération : c'est ce qui distingue une recherche
			// qui ne trouve rien d'une recherche réduite par les droits.
			j.Noter("hors-droits", écartées)
			if ldapjournal.TraceActive() {
				tracerLesEntreesHorsDroits(j, candidates, portée)
			}
		}
		candidates = retenues
	}
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
		j.Noter("matchedDN", fmt.Sprintf("%q", ancetre))
		response.SendLDAPNoSuchObject(conn, messageID, ancetre)
		return
	}

	// 2. Évaluer le filtre
	matched := candidate.Filtre(candidates, op.Filter, baseDN, op.Scope)

	// Le déroulé, APRÈS le filtre d'autorisation — et seulement s'il est demandé.
	//
	// Il avait lieu dans le résolveur, donc avant : le journal portait le contenu
	// des entrées que le compte n'a pas le droit de lire. Corriger la fuite vers
	// le client en la laissant vers le journal n'aurait rien corrigé. Ce qui est
	// vidé ici est ce que le compte PEUT lire, tel qu'il le lira.
	if ldapjournal.TraceActive() {
		tracerLeFiltrage(j, candidates, matched, op.Attributes)
	}

	// 3. Construire et envoyer les réponses, dans les limites.
	//
	// sizeLimit et timeLimit étaient décodés puis IGNORÉS. Un client qui demandait
	// une entrée recevait l'annuaire entier — et rien n'empêchait de le demander
	// en boucle.
	début := time.Now()

	if taille, paginée := taillePage(op, isBound); paginée {
		servirPremierePage(conn, messageID, op, username, baseDN, matched, taille, début)
		return
	}

	limite := effectiveSizeLimit(op.SizeLimit)
	tronquée := limite > 0 && len(matched) > limite
	if tronquée {
		matched = matched[:limite]
	}
	if !envoyerEntrees(conn, messageID, op, username, baseDN, matched, début) {
		return
	}
	if tronquée {
		j.Noter("tronquée-à", fmt.Sprintf("%d(demandé %d, borne serveur %d)",
			len(matched), op.SizeLimit, ldapstorage.MaxSearchEntries))
		response.SendLDAPSearchFailureCode(conn, messageID,
			ldapstorage.ResultSizeLimitExceeded, "size limit exceeded")
		return
	}

	response.SendLDAPSearchResultDone(conn, messageID)
}

// envoyerEntrees écrit les entrées d'une réponse, ou d'une page.
//
// Rend false quand l'envoi s'est arrêté avant la fin : le délai est dépassé —
// le code d'erreur est alors déjà parti — ou le client n'est plus là. Dans les
// deux cas l'appelant n'a plus rien à envoyer.
func envoyerEntrees(conn net.Conn, messageID int, op ldapstorage.SearchRequest, username, baseDN string,
	entrees []ldapinterface.LDAPEntry, début time.Time) bool {
	délai := effectiveTimeLimit(op.TimeLimit)
	avecDroits := droitsServiceDemandes(op.Attributes)

	for _, entry := range entrees {
		if délai > 0 && time.Since(début) > délai {
			ldapjournal.Ecrire(conn, "WARNING", logs.CodeNone, fmt.Sprintf(
				"recherche interrompue après %s sur baseDN=%s", délai, baseDN))
			response.SendLDAPSearchFailureCode(conn, messageID,
				ldapstorage.ResultTimeLimitExceeded, "time limit exceeded")
			return false
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
			ldapjournal.Ecrire(conn, "WARNING", logs.CodeNone, "envoi d'une entrée en échec : "+err.Error())
			return false
		}
	}
	return true
}

// EntreesTracees borne le nombre d'entrées que le déroulé d'UNE opération
// détaille.
//
// Le déroulé sert à comprendre pourquoi une recherche rend ce qu'elle rend, et
// les premières entrées suffisent à le voir. Sans borne, une lecture complète
// d'un annuaire de dix mille comptes écrirait dix mille vidages par recherche —
// le journal noyé que le TO-DO 145 corrige, revenu par le niveau TRACE.
const EntreesTracees = 20

// tracerLesEntreesHorsDroits nomme les entrées que le contrôle d'accès a
// écartées : le DN et les rattachements, PAS le contenu — ce sont précisément
// celles que le compte n'a pas le droit de lire, et les vider dans le journal
// ne ferait que déplacer la fuite.
func tracerLesEntreesHorsDroits(j *ldapjournal.Operation, candidats []ldapinterface.LDAPEntry, portée *security.PorteeDeRecherche) {
	écrites, tues := 0, 0
	for _, e := range candidats {
		if portée.AutoriseUnDes(e.Domaines()) {
			continue
		}
		if écrites == EntreesTracees {
			tues++
			continue
		}
		j.Trace("écartée par les droits : %q (rattachements %v)", e.DN(), e.Domaines())
		écrites++
	}
	if tues > 0 {
		j.Trace("… et %d autre(s) entrée(s) écartée(s) par les droits", tues)
	}
}

// tracerLeFiltrage vide les entrées que le filtre a retenues, telles que le
// compte les lira.
//
// C'est ce qui reste du déroulé que `candidate.Filtre` écrivait à chaque
// recherche — trois lignes par candidat. Il ne sort plus que sur demande
// (`ldap: trace`), sous l'identifiant de l'opération, et pour les
// EntreesTracees premières entrées.
//
// Les entrées ÉCARTÉES par le filtre ne sont pas nommées une à une : sur une
// recherche d'un compte dans un annuaire de dix mille, cela faisait dix mille
// lignes pour dire « pas celui-ci ». Leur nombre se lit sur la ligne de
// l'opération — candidats, moins entrées rendues.
func tracerLeFiltrage(j *ldapjournal.Operation, candidats, retenues []ldapinterface.LDAPEntry, attributs []string) {
	j.Trace("filtre : %d candidat(s), %d retenue(s), %d écartée(s)",
		len(candidats), len(retenues), len(candidats)-len(retenues))
	for i, e := range retenues {
		if i == EntreesTracees {
			j.Trace("… et %d autre(s) entrée(s) retenue(s)", len(retenues)-EntreesTracees)
			return
		}
		j.Trace("retenue par le filtre : %s", scope.DumpLDAPEntry(e, attributs))
	}
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
