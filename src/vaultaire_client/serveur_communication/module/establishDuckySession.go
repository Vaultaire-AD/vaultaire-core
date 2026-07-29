package module

import (
	"fmt"
	"net"
	"strconv"
	"time"
	"vaultaire_client/config"
	serveur "vaultaire_client/duckynetworkClient/serveurauth"
	"vaultaire_client/duckynetworkClient/userauth"
	"vaultaire_client/logs"
	"vaultaire_client/sessionmgr"
	"vaultaire_client/storage"
)

func EstablishDuckySession(user, pass string) (*storage.DuckySession, error) {
	servers := config.GetServers()
	if len(servers) == 0 {
		return nil, fmt.Errorf("aucun serveur configuré")
	}
	var lastErr error
	for _, server := range servers {
		serverAddr := server.IP + ":" + strconv.Itoa(server.Port)
		logs.Write_log("INFO", "Tentative connexion serveur "+serverAddr)
		conn, err := net.DialTimeout("tcp", serverAddr, 10*time.Second)
		if err != nil {
			logs.Write_log("WARNING", "Connexion impossible "+serverAddr+" : "+err.Error())
			lastErr = err
			continue
		}
		ds := &storage.DuckySession{
			Conn:      conn,
			SessionID: sessionmgr.NewSessionID(),
			IsSafe:    false,
		}
		// Gestion clé serveur
		if !HaveServeurKey() {
			logs.Write_log("INFO", "Clé serveur manquante, demande en cours...")
			_ = serveur.AskServerKey(ds)
		}
		// Authentification serveur
		ds.SessionKey = serveur.AskServerAuthentification(ds)
		if ds.SessionKey == nil {
			logs.Write_log("WARNING", "Authentification serveur échouée sur "+serverAddr)
			conn.Close()
			lastErr = fmt.Errorf("auth serveur échouée %s", serverAddr)
			continue
		}
		// Authentification utilisateur
		userauth.AskAuthentification(user, pass, ds)
		// Tout est OK
		logs.Write_log("INFO", "Connexion Vaultaire établie sur "+serverAddr)
		return ds, nil
	}

	return nil, fmt.Errorf(
		"aucun serveur Vaultaire disponible : %v",
		lastErr,
	)
}

// 	server := servers[0]
// 	serverAddr := server.IP + ":" + strconv.Itoa(server.Port)
// 	conn, err := net.DialTimeout("tcp", serverAddr, 10*time.Second)
// 	if err != nil {
// 		return nil, err
// 	}

// 	ds := &storage.DuckySession{
// 		Conn: conn,
// 		// SessionID est généré ici, avant toute poignée de main : la session
// 		// est adressable dès sa création, pas seulement une fois l'auth
// 		// terminée. Pour la session machine "vaultaire", cet ID est ensuite
// 		// remplacé par la clé réservée sessionmgr.MotherSessionID par
// 		// l'appelant (EnableServerCommunication).
// 		SessionID: sessionmgr.NewSessionID(),
// 		IsSafe:    false,
// 	}

// 	// Gestion des clés serveur
// 	if !HaveServeurKey() {
// 		logs.Write_log("INFO", "Clé serveur manquante, demande en cours...")
// 		_ = serveur.AskServerKey(ds)
// 	}

// 	// Authentification de la session (Echange de clé de session)
// 	ds.SessionKey = serveur.AskServerAuthentification(ds)

// 	// Authentification de l'utilisateur (Vaultaire login)
// 	userauth.AskAuthentification(user, pass, ds)

// 	return ds, nil
// }
