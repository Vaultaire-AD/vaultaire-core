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
		// Le « ! » n'est pas décoratif : on ne démarre une session QUE s'il n'y
		// en a aucune. Sans lui, la condition ne pouvait être vraie que si une
		// session existait déjà — cas déjà traité par la branche du dessus —,
		// donc aucune session n'était jamais lancée et la fonction expirait au
		// bout de 100 secondes sans rien dire d'autre que « tunnel pas prêt ».
	} else if !IsDuckySessionActive() {
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
