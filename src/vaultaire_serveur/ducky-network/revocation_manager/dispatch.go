// Package revocationmanager orchestre le kill switch : déclenchement, effet
// serveur immédiat, poussée vers le parc et rejeu des ordres non acquittés.
//
// Le kill switch a sa propre catégorie de trames (06) et n'emprunte rien au
// transport des GPO, alors que le format est proche. La raison tient en une
// ligne : les GPO sont tirées par le client au rythme qui l'arrange, une
// révocation est poussée par le serveur et ne peut pas attendre le prochain
// cycle. Les loger ensemble ferait dépendre une coupure d'urgence du
// rafraîchissement horaire des politiques.
package revocationmanager

import (
	"fmt"
	"strings"

	"vaultaire/core/database"
	dbrevocation "vaultaire/core/database/db_revocation"
	"vaultaire/core/domain"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
	"vaultaire/core/revocation"
	websession "vaultaire/core/web_serveur/session"
	"vaultaire/ducky-network/sendmessage"
	"vaultaire/ducky-network/sessionmgr"
)

// Outcome résume ce qu'un déclenchement a produit, pour l'affichage.
type Outcome struct {
	OrderID       int
	Mode          revocation.Mode
	Username      string
	TargetCount   int
	PushedNow     int
	SessionsKilled int
	DirectoryNote string
}

// Trigger déclenche une révocation.
//
// Ordre des opérations, et il n'est pas interchangeable :
//
//  1. contrôles (compte protégé, RBAC) — avant toute écriture ;
//  2. calcul des machines cibles — AVANT toute suppression, car en mode hard
//     l'appartenance aux groupes disparaît avec le compte et la liste
//     deviendrait vide ;
//  3. écriture de l'ordre, qui le rend durable et donc rejouable ;
//  4. effet serveur (suppression du compte en mode hard) ;
//  5. fermeture des sessions en cours ;
//  6. poussée aux machines connectées.
//
// Si l'étape 6 échoue en totalité — serveur isolé du parc — l'ordre reste en
// base et partira à la reconnexion des machines. C'est le point de l'étape 3.
func Trigger(senderUsername string, senderGroupIDs []int,
	targetUser string, mode revocation.Mode, reason revocation.Reason) (Outcome, error) {

	out := Outcome{Mode: mode, Username: targetUser}
	db := database.GetDatabase()
	if db == nil {
		return out, fmt.Errorf("base indisponible")
	}

	if !revocation.IsValidMode(mode) {
		return out, fmt.Errorf("mode inconnu %q", mode)
	}
	if !revocation.IsValidReason(reason) {
		return out, fmt.Errorf("motif inconnu %q", reason)
	}

	// Le nom peut arriver sous forme complète (admin@vaultaire.fr) : l'annuaire
	// ne connaît que la forme courte, mais c'est la forme complète qui doit
	// partir vers les machines, puisque c'est le nom du compte local.
	directoryUser, _ := domain.ExctractDomainFromUsername(targetUser)
	if strings.TrimSpace(directoryUser) == "" {
		return out, fmt.Errorf("utilisateur cible manquant")
	}

	if err := database.GuardProtectedUserRevocation(directoryUser, string(mode)); err != nil {
		return out, err
	}

	// RBAC : le droit est exigé sur TOUS les domaines de la cible. Un compte
	// présent dans plusieurs domaines ne se coupe pas depuis un seul d'entre
	// eux.
	domains, err := permission.GetDomainListFromUsername(directoryUser)
	if err != nil || len(domains) == 0 {
		domains = nil // aucune information de domaine : seul un droit global passe
	}
	if allowed, reason := permission.CheckPermissionsAllDomains(
		senderGroupIDs, permission.ActionKillSwitch, domains); !allowed {
		logs.Write_Log("SECURITY", fmt.Sprintf(
			"revocation: %s tente %s sur %s — %s", senderUsername, mode, directoryUser, reason))
		return out, fmt.Errorf("permission refusée : %s", reason)
	}
	// Le mode destructeur exige en plus le droit de supprimer un compte.
	if mode.IsDestructive() {
		if allowed, reason := permission.CheckPermissionsAllDomains(
			senderGroupIDs, "write:delete:user", domains); !allowed {
			logs.Write_Log("SECURITY", fmt.Sprintf(
				"revocation: %s tente une suppression via kill switch sur %s — %s",
				senderUsername, directoryUser, reason))
			return out, fmt.Errorf("permission refusée pour le mode hard : %s", reason)
		}
	}

	if _, err := database.Get_User_ID_By_Username(db, directoryUser); err != nil {
		return out, fmt.Errorf("utilisateur %s inconnu de l'annuaire", directoryUser)
	}

	// Étape 2 — avant toute suppression.
	targets, err := dbrevocation.MachinesSharingGroupWith(db, directoryUser)
	if err != nil {
		return out, fmt.Errorf("calcul des machines cibles : %w", err)
	}
	out.TargetCount = len(targets)

	// Le déverrouillage lève d'abord la marque en base, sinon le compte
	// resterait bloqué côté serveur alors que les machines le rouvrent.
	if mode == revocation.ModeUnlock {
		lifted, err := dbrevocation.LiftSoftRevocations(db, directoryUser, senderUsername)
		if err != nil {
			return out, fmt.Errorf("levée du verrouillage : %w", err)
		}
		if lifted == 0 {
			out.DirectoryNote = "aucun verrouillage actif à lever"
		}
	}

	orderID, err := dbrevocation.CreateOrder(db, directoryUser, mode, reason, senderUsername, targets)
	if err != nil {
		return out, err
	}
	out.OrderID = orderID

	if mode.IsDestructive() {
		if err := database.Command_DELETE_UserWithUsername(db, directoryUser); err != nil {
			// L'ordre est déjà écrit : les machines nettoieront leur compte
			// local même si l'annuaire résiste. On remonte l'erreur sans
			// annuler, parce qu'un compte compromis à moitié coupé vaut mieux
			// qu'un compte pas coupé du tout.
			out.DirectoryNote = "suppression annuaire en échec : " + err.Error()
			logs.Write_Log("ERROR", fmt.Sprintf(
				"revocation: ordre %d — suppression de %s dans l'annuaire échouée : %v",
				orderID, directoryUser, err))
		} else {
			out.DirectoryNote = "compte supprimé de l'annuaire"
		}
	}

	if mode != revocation.ModeUnlock {
		out.SessionsKilled = killSessions(directoryUser)
	}

	order := revocation.Order{ID: orderID, Mode: mode, Username: targetUser, Reason: reason}
	out.PushedNow = pushToOnline(order, targets)

	logs.Write_Log("SECURITY", fmt.Sprintf(
		"revocation: ordre %d appliqué — %s sur %s par %s ; %d machine(s) visée(s), %d jointe(s) immédiatement, %d session(s) fermée(s)",
		orderID, mode, directoryUser, senderUsername, out.TargetCount, out.PushedNow, out.SessionsKilled))

	return out, nil
}

// killSessions ferme TOUTES les sessions ouvertes au nom d'un utilisateur.
//
// Sans ça, une personne déjà connectée continuerait de travailler jusqu'à
// l'expiration de sa session : sur un compte compromis, c'est le temps qu'on
// cherche justement à supprimer.
//
// Les deux registres sont traités. Ne fermer que les sessions Ducky laissait le
// compte révoqué accéder à l'interface web pendant trente minutes : il ne
// pouvait plus rien faire — GetGroupIDsForUser lui refuse toutes ses
// permissions — mais il continuait de voir.
func killSessions(username string) int {
	ducky := sessionmgr.Sessions.ListAuthenticatedByUsername(username)
	for _, sess := range ducky {
		logs.Write_LogCodeMeta("WARNING", logs.CodeNone,
			"revocation: fermeture de la session Ducky de "+username,
			logs.WithMeta(sess.SessionID, username))
		sessionmgr.Sessions.RemoveSession(sess.SessionID)
	}

	web := websession.DeleteSessionsOf(username)
	if web > 0 {
		logs.Write_Log("WARNING", fmt.Sprintf(
			"revocation: %d session(s) web de %s fermée(s)", web, username))
	}

	// Les authentifications à mi-chemin comptent aussi.
	//
	// Un compte révoqué entre la saisie de son mot de passe et celle de son code
	// à usage unique conserverait sinon un jeton valant « mot de passe déjà
	// vérifié », et terminerait sa connexion après la coupure. La fenêtre est
	// courte — cinq minutes — mais c'est exactement la fenêtre pendant laquelle
	// on déclenche un kill switch sur quelqu'un qu'on voit se connecter.
	pending := websession.DeletePendingOf(username)
	if pending > 0 {
		logs.Write_Log("WARNING", fmt.Sprintf(
			"revocation: %d authentification(s) en cours de %s interrompue(s)", pending, username))
	}

	return len(ducky) + web + pending
}

// pushToOnline envoie l'ordre aux machines actuellement connectées.
//
// Retourne le nombre de machines jointes. Les autres ne sont pas perdues :
// leur ligne reste « pending » en base et l'ordre repart à la reconnexion, via
// 06_04. Un échec d'envoi n'est donc pas traité comme une erreur — c'est un
// simple « pas maintenant ».
func pushToOnline(order revocation.Order, targets []string) int {
	pushed := 0
	for _, computeurID := range targets {
		sess, ok := sessionmgr.Sessions.GetByClientSoftwareID(computeurID)
		if !ok || sess.DuckySession == nil {
			continue
		}
		msg := buildOrderFrame(sess.SessionID, order)
		if err := sendmessage.SendMessage(msg, computeurID, sess.DuckySession); err != nil {
			logs.Write_Log("WARNING", fmt.Sprintf(
				"revocation: ordre %d non remis à %s (sera rejoué) : %v", order.ID, computeurID, err))
			continue
		}
		pushed++
	}
	return pushed
}
