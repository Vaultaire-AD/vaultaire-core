package duckynetwork

import (
	keymanagement "vaultaire/serveur/ducky-network/key_management"
	sync "vaultaire/serveur/ducky-network/sync"
	"vaultaire/serveur/logs"
	"vaultaire/serveur/storage"
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
			logs.Write_LogCode("WARNING", logs.CodeNetConnection, "ducky: error accepting new connection: "+err.Error())
			continue
		}
		var duckysession storage.DuckySession
		duckysession.Conn = conn
		duckysession.IsSafe = false
		go handleConnection(&duckysession)
	}
}

// --- Point d'entrée ---

func StartDuckyServer() {
	initializeServer()

	if err := generateKeys(); err != nil {
		logs.Write_LogCode("CRITICAL", logs.CodeNetKey, "ducky: key generation failed")
		return
	}

	listener, err := createListener()
	if err != nil {
		logs.Write_LogCode("CRITICAL", logs.CodeNetConnection, "ducky: listener creation failed")
		return
	}

	logs.Write_Log("INFO", "ducky: server ready and listening on port "+storage.ServeurLisetenPort)

	acceptConnections(listener)
}
