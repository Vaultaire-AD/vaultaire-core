package pamcommunication

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"
	serveurcommunication "vaultaire_client/serveur_communication"
	"vaultaire_client/storage"
)

type Response struct {
	Status   string   `json:"status"`
	IsAdmin  bool     `json:"is_admin"` // Ce champ sera ignoré si false/non défini
	Ssh_keys []string `json:"ssh_keys"`
}

// Fonction pour gérer l'authentification
func handleAuthRequest(conn net.Conn, payload string) {
	var authReq AuthRequest
	err := json.Unmarshal([]byte(payload), &authReq)
	if err != nil {
		log.Printf("Erreur de décodage JSON auth: %v", err)
		return
	}

	if !isValidUserInput(authReq.User) || !isValidUserInput(authReq.Password) {
		log.Printf("Entrée invalide de l'utilisateur: %s", authReq.User)
		return
	}

	// Lancer l'ancien main avec les identifiants
	go serveurcommunication.EnableServerCommunication(authReq.User, authReq.Password)

	status_rep := "timeout"
	select {
	case auth_res := <-storage.Authentification_PAM:
		switch auth_res {
		case "success":
			fmt.Println("Authentification réussie:", auth_res)
			status_rep = "success"
		case "failed":
			fmt.Println("Authentification failed:", auth_res)
			status_rep = "failed"
		default:
			fmt.Println("Authentification status inconnu:", auth_res)
		}

	case <-time.After(5 * time.Second):
		fmt.Println("Time Out")
	}

	fmt.Println("L'user est il admin ? : " + strconv.FormatBool(storage.IsAdmin))
	// Envoyer une réponse confirmant l'authentification
	response := Response{
		Status:  status_rep,
		IsAdmin: storage.IsAdmin,
	}

	encoder := json.NewEncoder(conn)
	err = encoder.Encode(response)
	if err != nil {
		log.Printf("Erreur d'envoi de la réponse: %v", err)
	}
}
