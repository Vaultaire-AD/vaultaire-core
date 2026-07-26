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

func isValidUserInput(input string) bool {
	if input == "" {
		return false
	}
	validInputPattern := `^[a-zA-Z0-9._@-]+$`
	re := regexp.MustCompile(validInputPattern)
	return re.MatchString(input)
}

func handleUnixSocketConnection(conn net.Conn) {
	defer func() {
		if err := conn.Close(); err != nil {
			logs.Write_log("ERROR", fmt.Sprintf("Error closing connection: %v", err))
		}
	}()
	var message map[string]json.RawMessage
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&message); err != nil {
		logs.Write_log("ERROR", fmt.Sprintf("Erreur de decodage du message JSON: %v", err))
		return
	}

	// Routage : 'auth' et 'check' utilisent la même fonction générique
	if auth, exists := message["auth"]; exists {
		processPamRequest(conn, "AUTH", string(auth))

	} else if check, exists := message["check"]; exists {
		processPamRequest(conn, "CHECK", string(check))

	} else if closeMsg, exists := message["close"]; exists {
		handleCloseRequest(conn, string(closeMsg))

	} else {
		log.Printf("Commande inconnue reçue: %v", message)
	}
}

func UnixSocketServer() {
	if err := os.RemoveAll(storage.SocketPath); err != nil {
		logs.Write_log("CRITICAL", fmt.Sprintf("Error removing existing socket file: %v", err))
	}

	ln, err := net.Listen("unix", storage.SocketPath)
	if err != nil {
		logs.Write_log("CRITICAL", fmt.Sprintf("Error creating Unix socket: %v", err))
		return
	}
	defer func() {
		if err := ln.Close(); err != nil {
			logs.Write_log("CRITICAL", fmt.Sprintf("Error closing Unix socket: %v", err))
		}
	}()

	// Ajustement des permissions du socket Unix pour PAM
	os.Chmod(storage.SocketPath, 0666)

	logs.Write_log("INFO", fmt.Sprintf("Server listening on Unix socket: %s", storage.SocketPath))

	for {
		conn, err := ln.Accept()
		if err != nil {
			logs.Write_log("ERROR", fmt.Sprintf("Error accepting connection: %v", err))
			continue
		}
		go handleUnixSocketConnection(conn)
	}
}
