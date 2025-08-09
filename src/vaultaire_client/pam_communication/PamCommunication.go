package pamcommunication

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
)

type AuthRequest struct {
	User     string `json:"user"`
	Password string `json:"password"`
}

// Fonction pour valider les entrées de l'utilisateur
func isValidUserInput(input string) bool {
	validInputPattern := "^[a-zA-Z0-9._-]+$"
	re := regexp.MustCompile(validInputPattern)
	return re.MatchString(input)
}

// Fonction pour gérer la connexion socket Unix
func handleUnixSocketConnection(conn net.Conn) {
	defer conn.Close()

	// Décode le message JSON
	var message map[string]json.RawMessage
	decoder := json.NewDecoder(conn)
	err := decoder.Decode(&message)
	if err != nil {
		log.Printf("Erreur de décodage du message JSON: %v", err)
		return
	}

	// Vérifier le type de message et traiter en conséquence
	if auth, exists := message["auth"]; exists {
		// Traitement de la commande d'authentification
		handleAuthRequest(conn, string(auth))

	} else if close, exists := message["close"]; exists {
		// Traitement de la commande de fermeture
		handleCloseRequest(conn, string(close))

	} else {
		log.Printf("Commande inconnue reçue: %v", message)
	}
}

func UnixSocketServer() {
	socketPath := "/tmp/vaultaire_client.sock"

	// Supprimer le fichier du socket s'il existe déjà
	if err := os.RemoveAll(socketPath); err != nil {
		log.Fatalf("Error removing existing socket file: %v", err)
	}

	// Créer le socket Unix
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("Error creating Unix socket: %v", err)
	}
	defer func() {
		if err := ln.Close(); err != nil {
			// Handle or log the error
			fmt.Printf("erreur lors de la fermeture du fichier: %v", err)
		}
	}()

	fmt.Println("Server listening on Unix socket:", socketPath)

	// Boucle d'acceptation des connexions
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}

		// Gérer la connexion sur un goroutine séparée
		go handleUnixSocketConnection(conn)
	}
}
