package pamcommunication

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"vaultaire_client/duckynetworkClient/sendmessage"
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
			log.Printf("error closing connection: %v", err)
		}
	}()

	var closeReq CloseRequest
	err := json.Unmarshal([]byte(payload), &closeReq)
	if err != nil {
		log.Printf("Erreur de décodage JSON auth: %v", err)
		return
	}

	// Vérifier que l'action est bien "S_close"
	if closeReq.Action != "S_close" {
		log.Printf("Action invalide: %s", closeReq.Action)
		return
	}

	fmt.Printf("Fermeture de session pour l'utilisateur: %s\n", closeReq.User)
	connn, exist := serveurcommunication.GetConnection(closeReq.User)
	if !exist {
		fmt.Println("Unable to recover user tunnel connection to serveur")
	} else {
		message := "02_05\nserveur_central\n" + closeReq.User + "\n" + storage.Computeur_ID + "\nclose"
		sendmessage.SendMessage(message, connn)
		serveurcommunication.RemoveConnection(closeReq.User)
	}
}
