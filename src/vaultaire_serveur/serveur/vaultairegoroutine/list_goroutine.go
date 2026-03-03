package vaultairegoroutine

import (
	"vaultaire/serveur/api"
	"vaultaire/serveur/command"
	"vaultaire/serveur/logs"
	"vaultaire/serveur/storage"
	"net"
	"os"
)

// Démarre le serveur UNIX pour écouter les commandes CLI
func StartUnixSocketServer() {

	err := os.Remove(storage.SocketPath)
	if err != nil && !os.IsNotExist(err) {
		logs.Write_LogCode("ERROR", logs.CodeFileSocket, "socket: remove existing socket file failed: "+err.Error())
	}

	listener, err := net.Listen("unix", storage.SocketPath)
	if err != nil {
		logs.Write_LogCode("CRITICAL", logs.CodeFileSocket, "socket: failed to create UNIX socket: "+err.Error())
		os.Exit(1)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			logs.Write_Log("DEBUG", "socket: listener close failed: "+err.Error())
		}
	}()
	logs.Write_Log("INFO", "socket: server ready, waiting for commands")

	// Boucle pour accepter les connexions
	for {
		conn, err := listener.Accept()
		if err != nil {
			logs.Write_LogCode("WARNING", logs.CodeFileSocket, "socket: accept error: "+err.Error())
			continue
		}
		go command.HandleClientCLI(conn)
	}
}

func StartAPI() {
	api.StartAPI()
}
