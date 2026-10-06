package pamcommunication

import (
	"encoding/json"
	"fmt"
	"net"

	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/sendmessage"
	"duckynetworkclient/V1/duckynetwork/storage"
	sto_session "duckynetworkclient/V1/duckynetwork/storage/stosession"
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
//
// # Ce qu'elle fait de nouveau : prévenir le core (03_11)
//
// Ne plus rien fermer avait un effet de bord : le core n'apprenait JAMAIS
// qu'une personne s'était déconnectée. Sa ligne de session restait affichée
// dans `status -u` jusqu'à expiration — et comme le battement de la machine
// prolonge les sessions de ses utilisateurs, « jusqu'à expiration » voulait
// dire « tant que la machine est allumée ».
//
// 03_11 dit donc au core d'effacer cette ligne, et rien d'autre. Elle passe par
// le tunnel machine, comme l'authentification, et ne ferme aucune connexion :
// c'est précisément pourquoi ce n'est pas un 02_05.
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

	signalerFinDeSession(closeReq.User)

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

// signalerFinDeSession émet 03_11 dans le tunnel machine.
//
// # Une lecture NON bloquante de la session
//
// GetValidVaultaireSession, et non WaitForVaultaireSession : la fermeture PAM
// est appelée par le système pendant une déconnexion, et l'attente pouvait
// durer jusqu'à cent secondes. Faire patienter une fermeture de session pour
// rafraîchir un tableau de bord serait un mauvais échange — d'autant que le
// tunnel absent signifie généralement que le core est injoignable, auquel cas
// l'attente ne servirait à rien non plus.
//
// # Pourquoi l'échec n'est que journalisé
//
// La personne est partie ; il n'y a rien à annuler. Sans cette trame, la ligne
// de session reste affichée jusqu'à l'extinction de la machine — un défaut
// d'affichage, pas un défaut de sécurité : un compte révoqué l'est par le kill
// switch, qui ne passe pas par ici.
func signalerFinDeSession(utilisateur string) {
	session := sto_session.SessionsUser.GetValidVaultaireSession()
	if session == nil || session.DuckySession == nil {
		logs.Write_log("WARNING", fmt.Sprintf(
			"Fin de session de %s non signalée au core : aucun tunnel machine établi", utilisateur))
		return
	}

	trame := sendmessage.BuildClientTrame("03_11", "serveur_central",
		string(session.DuckySession.SessionKey), "vaultaire", storage.Computeur_ID,
		utilisateur)
	sendmessage.SendMessage(trame, session.DuckySession)

	logs.Write_log("DEBUG", fmt.Sprintf("03_11 envoyée : fin de session de %s", utilisateur))
}
