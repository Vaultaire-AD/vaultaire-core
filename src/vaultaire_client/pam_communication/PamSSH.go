package pamcommunication

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
	"vaultaire_client/logs"
	serveurcommunication "vaultaire_client/serveur_communication"
	"vaultaire_client/storage"
	"vaultaire_client/tools/sshreq"
)

type CheckRequest struct {
	User string `json:"user"`
}

func handleCheckRequest(conn net.Conn, payload string) {
	var req CheckRequest
	err := json.Unmarshal([]byte(payload), &req)
	if err != nil {
		logs.Write_log("ERROR", fmt.Sprintf("Erreur de décodage JSON check: %v", err))
		return
	}

	if !isValidUserInput(req.User) {
		logs.Write_log("ERROR", fmt.Sprintf("Entrée invalide dans check: %s", req.User))
		return
	}
	logs.Write_log("INFO", fmt.Sprintf("PAM Check request for user: %s", req.User))

	// 🔐 channel privé pour cette requête
	respChan := make(chan string, 1)
	sshreq.Register(req.User, respChan)

	// lance la requête réseau
	go serveurcommunication.EnableServerCommunication("vaultaire", "vaultaire", req.User)

	status_rep := "timeout"

	fmt.Println("L'user est il admin ? : " + strconv.FormatBool(storage.IsAdmin))
	// Envoyer une réponse confirmant l'authentification
	sshKey := ""
	select {
	case sshKey = <-respChan:
		logs.Write_log("INFO", fmt.Sprintf("Clés publiques reçues pour l'utilisateur %s: %d clés", req.User, len(sshKey)))
		status_rep = "success"

	case <-time.After(5 * time.Second):
		logs.Write_log("ERROR", "Timeout récupération des clés publiques")
		sshreq.Remove(req.User) // cleanup registry
		sshKey = ""
		status_rep = "failed"
	}

	response := Response{
		Status:   status_rep,
		IsAdmin:  storage.IsAdmin,
		Ssh_keys: cleankey(sshKey),
	}

	encoder := json.NewEncoder(conn)
	err = encoder.Encode(response)
	if err != nil {
		logs.Write_log("ERROR", fmt.Sprintf("Erreur d'envoi réponse check: %v", err))
	}
	storage.IsAdmin = false
}

func cleankey(sshKey string) []string {
	rawKeys := strings.Split(sshKey, "\n")
	sshKeys := make([]string, 0, len(rawKeys))

	for _, k := range rawKeys {
		k = strings.TrimSpace(k)
		if k != "" {
			sshKeys = append(sshKeys, k)
		}
	}
	return sshKeys
}
