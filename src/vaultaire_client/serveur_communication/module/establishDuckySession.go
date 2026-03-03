package module

import (
	"net"
	"time"
	serveur "vaultaire_client/duckynetworkClient/serveurauth"
	"vaultaire_client/duckynetworkClient/userauth"
	"vaultaire_client/logs"
	"vaultaire_client/storage"
)

func EstablishDuckySession(user, pass string) (*storage.DuckySession, error) {
	serverAddr := storage.C_serveurIP + ":" + storage.C_serveurListenPort
	conn, err := net.DialTimeout("tcp", serverAddr, 10*time.Second)
	if err != nil {
		return nil, err
	}

	ds := &storage.DuckySession{
		Conn:   conn,
		IsSafe: false,
	}

	// Gestion des clés serveur
	if !HaveServeurKey() {
		logs.Write_log("INFO", "Clé serveur manquante, demande en cours...")
		_ = serveur.AskServerKey(ds)
	}

	// Authentification de la session (Echange de clé de session)
	ds.SessionKey = serveur.AskServerAuthentification(ds)

	// Authentification de l'utilisateur (Vaultaire login)
	userauth.AskAuthentification(user, pass, ds)

	return ds, nil
}
