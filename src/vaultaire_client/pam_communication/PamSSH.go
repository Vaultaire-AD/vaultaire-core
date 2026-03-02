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
	User     string `json:"user"`
	Password string `json:"password"`
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

	// 🔐 channel de type AuthResult
	respChan := make(chan storage.AuthResult, 1)
	sshreq.Register(req.User, respChan)

	// lance la requête réseau
	go serveurcommunication.EnableServerCommunication("vaultaire", "vaultaire", req.User, &req.Password, false)

	status_rep := "failed"
	isAdminResult := false

	fmt.Println("L'user est il admin ? : " + strconv.FormatBool(storage.IsAdmin))
	// Envoyer une réponse confirmant l'authentification

	select {
	case result := <-respChan:
		// On récupère tout d'un coup !
		isAdminResult = result.IsAdmin

		logs.Write_log("INFO", fmt.Sprintf("User %s authentifié. Admin: %t", req.User, isAdminResult))
		status_rep = "success"

	case <-time.After(7 * time.Second):
		logs.Write_log("ERROR", "Timeout ou Auth Failed pour "+req.User)
		sshreq.Remove(req.User)
	}

	// On nettoie le mot de passe après usage ou timeout
	req.Password = ""

	// Construction de la réponse pour le module PAM (JSON)
	response := Response{
		Status:  status_rep,
		IsAdmin: isAdminResult, // Utilisation du résultat serveur
	}

	encoder := json.NewEncoder(conn)
	err = encoder.Encode(response)
	if err != nil {
		logs.Write_log("ERROR", fmt.Sprintf("Erreur d'envoi réponse check: %v", err))
	}
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
