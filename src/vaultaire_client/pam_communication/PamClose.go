package pamcommunication

import (
	"duckynetworkclient/V1/duckynetwork/logs"
	sto_session "duckynetworkclient/V1/duckynetwork/storage/stosession"
	"encoding/json"
	"fmt"
	"net"
)

type CloseRequest struct {
	User   string `json:"user"`
	Action string `json:"action"`
}

// handleCloseRequest traite la fermeture de session PAM d'un utilisateur.
//
// # Ce que la fermeture NE fait PAS : toucher au tunnel machine
//
// Depuis la suppression du défi (03_04/03_05), l'authentification PAM passe
// À L'INTÉRIEUR du tunnel machine (`vaultaire`) : aucune session Ducky n'est
// ouverte au nom de l'utilisateur. Il n'y a donc, côté réseau, rien à fermer
// quand il se déconnecte.
//
// Une version cherchait la session du compte (introuvable, donc sans effet),
// une autre ciblait « vaultaire » — c'est-à-dire le TUNNEL MACHINE. Chaque
// déconnexion propre coupait alors le lien de toute la machine :
//
//   - la trame 02_05 envoyée était mal formée (la clé de session manquait) :
//     le core la rejetait comme usurpation et fermait la connexion ;
//   - le core effaçait la ligne `did_login` de la machine, qui disparaissait
//     de `status -c` ;
//   - le tunnel ne revenait qu'au terme de la reconnexion, et plus du tout sur
//     les agents antérieurs au correctif `Persistent`.
//
// La fermeture ne touche donc plus au tunnel. Elle retire seulement une
// éventuelle session propre au compte (l'ancien mode « client simple »), et
// jamais une session `vaultaire`.
func handleCloseRequest(conn net.Conn, payload string) {
	defer conn.Close()

	var closeReq CloseRequest
	if err := json.Unmarshal([]byte(payload), &closeReq); err != nil {
		logs.Write_log("ERROR", fmt.Sprintf("Erreur de décodage JSON close: %v", err))
		return
	}
	if closeReq.Action != "S_close" {
		logs.Write_log("ERROR", fmt.Sprintf("Action invalide dans close: %s", closeReq.Action))
		return
	}

	logs.Write_log("INFO", fmt.Sprintf("Fermeture de session PAM pour %s", closeReq.User))

	if closeReq.User == "" || closeReq.User == "vaultaire" {
		// Le tunnel machine ne se ferme jamais sur une déconnexion PAM.
		logs.Write_log("WARNING", fmt.Sprintf(
			"Fermeture demandée pour %q : le tunnel machine n'est pas fermé par PAM", closeReq.User))
		return
	}

	target, ok := sto_session.SessionsUser.ResolveForClose(closeReq.User)
	if !ok || target == nil || target.Username != closeReq.User {
		// Cas normal : l'authentification est passée par le tunnel machine,
		// aucune session propre au compte n'existe.
		logs.Write_log("DEBUG", fmt.Sprintf(
			"Aucune session Ducky propre à %s : rien à fermer, le tunnel machine reste ouvert", closeReq.User))
		return
	}

	sto_session.SessionsUser.RemoveSession(target.SessionID)
	logs.Write_log("INFO", fmt.Sprintf("Session Ducky de %s (id=%s) retirée", closeReq.User, target.SessionID))
}
