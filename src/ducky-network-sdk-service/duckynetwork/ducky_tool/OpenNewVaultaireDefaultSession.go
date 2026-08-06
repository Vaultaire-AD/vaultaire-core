package duckytool

import (
	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/storage/stosession"
	serveurcommunication "duckynetworkclient/V1/serveur_communication"
	"duckynetworkclient/V1/sessionmgr"
	"time"
)

func OpenVaultaireDefaultSession() *sessionmgr.Session {

	var sess *sessionmgr.Session
	tunnelReady := false

	// Si aucune session Vaultaire n'existe déjà, on en démarre une nous-même
	if s := stosession.SessionsUser.GetValidVaultaireSession(); s != nil {
		sess = s
		tunnelReady = true
	} else if IsDuckySessionActive() {
		logs.Write_log("INFO", "Aucune session Vaultaire active, démarrage d'une nouvelle session")
		go serveurcommunication.EnableServerCommunication("vaultaire", "vaultaire")
	}

	if !tunnelReady {
		for i := 0; i < 2000; i++ { // Timeout de 100s (500 * 200ms)
			if s := stosession.SessionsUser.GetValidVaultaireSession(); s != nil {
				sess = s
				tunnelReady = true
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
	}

	if !tunnelReady {
		logs.Write_log("ERROR", "Le tunnel n'est pas devenu prêt à temps")
		return nil
	}
	return sess
}
