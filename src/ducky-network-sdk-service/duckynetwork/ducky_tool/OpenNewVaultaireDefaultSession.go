package duckytool

import (
	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/storage/stosession"
	serveurcommunication "duckynetworkclient/V1/serveur_communication"
	"duckynetworkclient/V1/sessionmgr"
	"time"
)

// DemarrerSessionMachine ouvre la session machine quand il n'en existe aucune.
//
// # Pourquoi une variable et non un appel direct
//
// Tous les programmes du socle n'ouvrent pas leur session de la même façon.
// L'agent garde sa propre boucle de connexion : elle lit une configuration au
// format JSON, déjà déployée sur le parc, là où le SDK lit du YAML. Fusionner
// les deux formats obligerait à réécrire le fichier de configuration de chaque
// machine — pour un gain nul, puisque les deux décrivent la même chose.
//
// L'indirection laisse donc chaque programme fournir sa boucle, sans dupliquer
// OpenVaultaireDefaultSession, qui est identique pour tout le monde : c'est elle
// que le canal PAM appelle à chaque authentification.
//
// À remplacer AVANT le premier appel, dans le main du programme.
var DemarrerSessionMachine = func() {
	serveurcommunication.EnableServerCommunication("vaultaire", "vaultaire")
}

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
		// logs.Go et non « go » : une panique dans la boucle de connexion
		// tuerait tout le processus, pas seulement cette goroutine.
		logs.Go("communication serveur", DemarrerSessionMachine)
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
