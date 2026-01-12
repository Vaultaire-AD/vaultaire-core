package duckynetwork

import (
	keymanagement "DUCKY/serveur/ducky-network/key_management"
	sync "DUCKY/serveur/ducky-network/sync"
	"DUCKY/serveur/logs"
	"DUCKY/serveur/storage"
	"fmt"
	"net"
)

// --- Initialisation globale ---

func initializeServer() {
	sync.Sync_InitMapDuckyIntegrity()
	go clearSession()
	go checkServeurOnline()
}

// --- Gestion des clés ---

func generateKeys() error {
	if err := keymanagement.Generate_Serveur_Key_Pair(); err != nil {
		logs.Write_Log("CRITICAL", "Error generating server key pair: "+err.Error())
		return err
	}
	if err := keymanagement.Generate_SSH_Key_For_Login_Client(); err != nil {
		logs.Write_Log("CRITICAL", "Error generating SSH key for login client: "+err.Error())
		return err
	}
	return nil
}

// --- Mise en place du listener ---

func createListener() (net.Listener, error) {
	listener, err := net.Listen("tcp", ":"+storage.ServeurLisetenPort)
	if err != nil {
		logs.Write_Log("CRITICAL", "Error listening on port "+storage.ServeurLisetenPort+": "+err.Error())
		return nil, err
	}
	return listener, nil
}

// --- Boucle principale ---

func acceptConnections(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			logs.Write_Log("WARNING", "Error accepting new connection: "+err.Error())
			fmt.Println("Error accepting new connection:", err)
			continue
		}
		var duckysession storage.DuckySession
		duckysession.Conn = conn
		go handleConnection(&duckysession)
	}
}

// --- Point d'entrée ---

func StartDuckyServer() {
	initializeServer()

	if err := generateKeys(); err != nil {
		fmt.Println("Key generation failed, check logs.")
		return
	}

	listener, err := createListener()
	if err != nil {
		fmt.Println("Listener creation failed, check logs.")
		return
	}

	fmt.Println("Server is ready and listening on port " + storage.ServeurLisetenPort + " ...")
	logs.Write_Log("INFO", "Server is ready and listening on port "+storage.ServeurLisetenPort+" ...")

	acceptConnections(listener)
}
