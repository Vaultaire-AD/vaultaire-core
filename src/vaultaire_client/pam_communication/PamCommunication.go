package pamcommunication

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"vaultaire_client/logs"
	"vaultaire_client/storage"
)

type AuthRequest struct {
	User     string `json:"user"`
	Password string `json:"password"`
}

// Fonction pour valider les entrées de l'utilisateur
func isValidUserInput(input string) bool {
	validInputPattern := "^[a-zA-Z0-9._@-]+$"
	re := regexp.MustCompile(validInputPattern)
	return re.MatchString(input)
}

// Fonction pour gérer la connexion socket Unix
func handleUnixSocketConnection(conn net.Conn) {
	defer func() {
		if err := conn.Close(); err != nil {
			// Handle or log the error
			logs.Write_log("ERROR", fmt.Sprintf("Error closing connection: %v", err))
		}
	}()

	// Décode le message JSON
	var message map[string]json.RawMessage
	decoder := json.NewDecoder(conn)
	err := decoder.Decode(&message)
	if err != nil {
		logs.Write_log("ERROR", fmt.Sprintf("Erreur de décodage du message JSON: %v", err))
		return
	}

	// Vérifier le type de message et traiter en conséquence
	if auth, exists := message["auth"]; exists {
		// Traitement de la commande d'authentification
		handleAuthRequest(conn, string(auth))

	} else if close, exists := message["close"]; exists {
		// Traitement de la commande de fermeture
		handleCloseRequest(conn, string(close))

	} else if check, exists := message["check"]; exists {
		handleCheckRequest(conn, string(check))
	} else {
		log.Printf("Commande inconnue reçue: %v", message)
	}
}

func UnixSocketServer() {

	// Supprimer le fichier du socket s'il existe déjà
	if err := os.RemoveAll(storage.SocketPath); err != nil {
		logs.Write_log("CRITICAL", fmt.Sprintf("Error removing existing socket file: %v", err))
	}

	// Créer le socket Unix
	ln, err := net.Listen("unix", storage.SocketPath)
	if err != nil {
		logs.Write_log("CRITICAL", fmt.Sprintf("Error creating Unix socket: %v", err))
	}
	defer func() {
		if err := ln.Close(); err != nil {
			// Handle or log the error
			logs.Write_log("CRITICAL", fmt.Sprintf("Error closing Unix socket: %v", err))
		}
	}()

	logs.Write_log("INFO", fmt.Sprintf("Server listening on Unix socket: %s", storage.SocketPath))

	// Boucle d'acceptation des connexions
	for {
		conn, err := ln.Accept()
		if err != nil {
			logs.Write_log("ERROR", fmt.Sprintf("Error accepting connection: %v", err))
			continue
		}

		// Gérer la connexion sur un goroutine séparée
		go handleUnixSocketConnection(conn)
	}
}
