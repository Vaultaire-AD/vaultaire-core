package pamcommunication

import (
	"encoding/json"
	"fmt"
	"net"
	"vaultaire_client/duckynetworkClient/sendmessage"
	"vaultaire_client/logs"
	"vaultaire_client/storage"
	sto_session "vaultaire_client/storage/stosession"
)

type CloseRequest struct {
	User   string `json:"user"`
	Action string `json:"action"`
}

func handleCloseRequest(conn net.Conn, payload string) {
	// Fermeture du socket local (celui qui a envoyé la requête JSON)
	defer conn.Close()

	var closeReq CloseRequest
	err := json.Unmarshal([]byte(payload), &closeReq)
	if err != nil {
		logs.Write_log("ERROR", fmt.Sprintf("Erreur de décodage JSON close: %v", err))
		return
	}

	if closeReq.Action != "S_close" {
		logs.Write_log("ERROR", fmt.Sprintf("Action invalide dans close: %s", closeReq.Action))
		return
	}

	logs.Write_log("INFO", fmt.Sprintf("Demande de fermeture de session reçue pour: %s", closeReq.User))

	// Le hook PAM ne connaît que le username, pas le SessionID. ResolveForClose
	// détermine QUELLE session cibler :
	//   - username normal : la session correspondante (la plus récente s'il y
	//     en a plusieurs) ;
	//   - "vaultaire" : la session machine la plus récente, sauf s'il n'en
	//     reste qu'une et que ce noeud est un serveur (auquel cas on refuse,
	//     ok=false, pour ne pas couper le tunnel machine).
	target, ok := sto_session.SessionsUser.ResolveForClose(closeReq.User)
	if !ok {
		logs.Write_log("WARNING", fmt.Sprintf(
			"Tentative de fermeture pour %s : aucune session fermable trouvée (déjà fermée, ou dernière session machine protégée)",
			closeReq.User))
		return
	}
	duckysession := target.DuckySession

	// 1. Préparer et envoyer le message de clôture au serveur central,
	// sur la connexion de la session ciblée
	message := fmt.Sprintf("02_05\nserveur_central\n%s\n%s\nclose", closeReq.User, storage.Computeur_ID)
	sendmessage.SendMessage(message, duckysession)

	// 2. NETTOYAGE CRITIQUE : on supprime des deux côtés, par SessionID (pas
	// par username, qui peut correspondre à plusieurs sessions)
	sto_session.SessionsUser.RemoveSession(target.SessionID)

	logs.Write_log("INFO", fmt.Sprintf(
		"Session %s (id=%s) proprement fermée et retirée des registres", closeReq.User, target.SessionID))
}
