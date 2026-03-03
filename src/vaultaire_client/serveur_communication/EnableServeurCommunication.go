package serveurcommunication

import (
	"fmt"
	"os"
	"time"
	"vaultaire_client/logs"
	"vaultaire_client/serveur_communication/module"
	"vaultaire_client/sessionmgr"
	sto_session "vaultaire_client/storage/stosession"
)

// Fonction pour gérer la requete au serveur central
func EnableServerCommunication(user, pass, sshUser string, sshpassword *string, isFetchBrut bool) {
	logs.Print_Log("Launching Vaultaire_Client_Network: " + user)

	if user == "vaultaire" {
		for {
			ds, err := module.EstablishDuckySession(user, pass)
			if err != nil {
				logs.Write_log("ERROR", fmt.Sprintf("Connexion échouée: %v", err))
				time.Sleep(30 * time.Second)
				continue
			}

			sto_session.SessionsUser.AddOrUpdate(user, ds.Conn, sessionmgr.SessionPending, ds)

			done := make(chan struct{})
			go func() {
				handleConnection(user, ds)
				close(done)
			}()

			// Si on a une demande SSH spécifique à passer dans ce tunnel
			if sshUser != "" && sshpassword != nil && *sshpassword != "" {
				module.WaitForSSHAuth(user, sshUser, sshpassword, ds)
			} else if isFetchBrut {
				module.WaitForSSHFetch(user, sshUser, ds)
				// 🔥 AJOUTE CECI :
				logs.Write_log("INFO", "Fin du mode Fetch, fermeture du programme.")
				os.Exit(0) // On force l'arrêt propre du binaire
			}

			<-done // Attend la fin de la connexion
			logs.Write_log("WARNING", "Flux arrêté. Reconnexion dans 30s...")
			time.Sleep(30 * time.Second)
		}
	} else {
		// Mode Client Simple (One-shot)
		ds, err := module.EstablishDuckySession(user, pass)
		if err != nil {
			logs.Write_log("ERROR", fmt.Sprintf("Erreur connexion client: %v", err))
			return
		}
		handleConnection(user, ds)
	}
}
