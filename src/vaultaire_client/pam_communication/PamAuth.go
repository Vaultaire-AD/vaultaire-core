package pamcommunication

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
	"vaultaire_client/logs"
	serveurcommunication "vaultaire_client/serveur_communication"
	"vaultaire_client/storage"
)

type Response struct {
	Status   string   `json:"status"`
	IsAdmin  bool     `json:"is_admin"`
	Ssh_keys []string `json:"ssh_keys"`
}

func handleAuthRequest(conn net.Conn, payload string) {
	var authReq AuthRequest
	err := json.Unmarshal([]byte(payload), &authReq)
	if err != nil {
		logs.Write_log("ERROR", fmt.Sprintf("Erreur JSON auth: %v", err))
		return
	}

	if !isValidUserInput(authReq.User) || !isValidUserInput(authReq.Password) {
		logs.Write_log("ERROR", fmt.Sprintf("Entrée invalide auth: %s", authReq.User))
		return
	}

	go serveurcommunication.EnableServerCommunication(authReq.User, authReq.Password, "")

	status_rep := "timeout"

	select {
	case auth_res := <-storage.Authentification_PAM:
		if auth_res == "success" {
			status_rep = "success"
			logs.Write_log("INFO", "Auth PAM succès "+authReq.User)
		} else {
			status_rep = "failed"
			logs.Write_log("ERROR", "Auth PAM failed "+authReq.User)
		}

	case <-time.After(5 * time.Second):
		logs.Write_log("ERROR", "Timeout auth")
	}

	response := Response{
		Status:   status_rep,
		IsAdmin:  storage.IsAdmin,
		Ssh_keys: []string{}, // ❗ pas ici
	}

	encoder := json.NewEncoder(conn)
	err = encoder.Encode(response)
	if err != nil {
		logs.Write_log("ERROR", fmt.Sprintf("Erreur envoi réponse: %v", err))
	}

	storage.IsAdmin = false
}
