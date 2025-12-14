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

type CheckRequest struct {
	User string `json:"user"`
}

func handleCheckRequest(conn net.Conn, payload string) {
	var req CheckRequest
	err := json.Unmarshal([]byte(payload), &req)
	if err != nil {
		log.Printf("Erreur de décodage JSON check: %v", err)
		return
	}

	if !isValidUserInput(req.User) {
		log.Printf("Entrée invalide dans check: %s", req.User)
		return
	}
	fmt.Println("PAM Check request for user :", req.User)
	// Vérification de l'utilisateur sur ton backend
	go serveurcommunication.EnableServerCommunication("vaultaire", "vaultaire", req.User)

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
	sshKeys := ""
	select {
	case sshKeys = <-storage.Authentification_SSHpubkey:
		fmt.Println("Clés publiques reçues :", sshKeys)

	case <-time.After(5 * time.Second):
		fmt.Println("Timeout récupération des clés publiques")
		sshKeys = "" // aucune clé reçue
	}

	response := Response{
		Status:   status_rep,
		IsAdmin:  storage.IsAdmin,
		Ssh_keys: sshKeys,
	}

	encoder := json.NewEncoder(conn)
	err = encoder.Encode(response)
	if err != nil {
		log.Printf("Erreur d'envoi réponse check: %v", err)
	}
	storage.IsAdmin = false
	storage.Authentification_SSHpubkey <- ""
}
