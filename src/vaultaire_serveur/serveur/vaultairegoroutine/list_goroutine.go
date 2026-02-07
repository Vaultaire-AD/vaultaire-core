package vaultairegoroutine

import (
	"vaultaire/serveur/api"
	"vaultaire/serveur/command"
	"vaultaire/serveur/logs"
	"vaultaire/serveur/storage"
	"fmt"
	"net"
	"os"
)

// Démarre le serveur UNIX pour écouter les commandes CLI
func StartUnixSocketServer() {

	err := os.Remove(storage.SocketPath)
	if err != nil && !os.IsNotExist(err) {
		logs.Write_Log("ERROR", "Error removing existing socket file: "+err.Error())
		fmt.Println("Erreur lors de la suppression du fichier de socket existant :", err)
	}

	listener, err := net.Listen("unix", storage.SocketPath)
	if err != nil {
		fmt.Println("Erreur création socket UNIX:", err)
		os.Exit(1)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
		}
	}()
	fmt.Println("Serveur en attente de commandes...")

	// Boucle pour accepter les connexions
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Erreur connexion client :", err)
			continue
		}
		go command.HandleClientCLI(conn)
	}
}

func StartAPI() {
	api.StartAPI()
}
