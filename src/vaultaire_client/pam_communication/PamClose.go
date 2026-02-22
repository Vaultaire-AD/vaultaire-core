package pamcommunication

import (
	"encoding/json"
	"fmt"
	"net"
	"vaultaire_client/duckynetworkClient/sendmessage"
	"vaultaire_client/logs"
	serveurcommunication "vaultaire_client/serveur_communication"
	"vaultaire_client/storage"
)

type CloseRequest struct {
	User   string `json:"user"`
	Action string `json:"action"`
}

// Fonction pour gérer les requêtes "close"
func handleCloseRequest(conn net.Conn, payload string) {
	defer func() {
		if err := conn.Close(); err != nil {
			// Handle or log the error
			logs.Write_log("ERROR", fmt.Sprintf("Error closing connection: %v", err))
		}
	}()

	var closeReq CloseRequest
	err := json.Unmarshal([]byte(payload), &closeReq)
	if err != nil {
		logs.Write_log("ERROR", fmt.Sprintf("Erreur de décodage JSON close: %v", err))
		return
	}

	// Vérifier que l'action est bien "S_close"
	if closeReq.Action != "S_close" {
		logs.Write_log("ERROR", fmt.Sprintf("Action invalide dans close: %s", closeReq.Action))
		return
	}
	logs.Write_log("INFO", fmt.Sprintf("Fermeture de session pour l'utilisateur: %s", closeReq.User))
	duckysession, exist := serveurcommunication.GetConnection(closeReq.User)
	if !exist {
		logs.Write_log("ERROR", "Impossible de récupérer la session utilisateur")
	} else {
		message := "02_05\nserveur_central\n" + closeReq.User + "\n" + storage.Computeur_ID + "\nclose"
		sendmessage.SendMessage(message, &duckysession)
		serveurcommunication.RemoveConnection(closeReq.User)
	}
}
