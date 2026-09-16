package vaultairegoroutine

import (
	"net"
	"os"
	"vaultaire/core/api"
	"vaultaire/core/command"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
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

	// Toute commande reçue ici s'exécute en tant que « vaultaire », sans
	// authentification (voir command.HandleClientCLI) : ce socket EST un accès
	// superadmin. Sa seule protection est donc le mode du fichier.
	//
	// net.Listen le crée en 0777 & ^umask. Le umask n'est fixé nulle part dans
	// le projet : sur un umask permissif (002, 000), le socket devenait
	// accessible au groupe ou à tout le monde, et n'importe quel processus
	// local obtenait l'annuaire complet. On ne laisse pas ça à une variable
	// d'environnement.
	//
	// 0600 : seul le propriétaire du processus serveur peut s'y connecter. Le
	// serveur tourne en root (systemd User=root, image pre-prod USER root),
	// donc en pratique seul root utilise le chemin local.
	if err := os.Chmod(storage.SocketPath, 0o600); err != nil {
		logs.Write_LogCode("CRITICAL", logs.CodeFileSocket,
			"socket: impossible de restreindre les permissions du socket, arrêt: "+err.Error())
		if cerr := listener.Close(); cerr != nil {
			logs.Write_Log("DEBUG", "socket: listener close failed: "+cerr.Error())
		}
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
