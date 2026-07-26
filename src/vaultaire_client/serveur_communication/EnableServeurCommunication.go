package serveurcommunication

import (
	"fmt"
	"time"
	"vaultaire_client/logs"
	"vaultaire_client/serveur_communication/module"
	"vaultaire_client/sessionmgr"
	"vaultaire_client/storage"
	sto_session "vaultaire_client/storage/stosession"
)

// Fonction pour gérer la requete au serveur central
func EnableServerCommunication(user, pass string) {
	logs.Print_Log("Launching Vaultaire_Client_Network: " + user)

	if user == "vaultaire" {
		for {
			var err error
			storage.DuckySessionLive, err = module.EstablishDuckySession(user, pass)
			if err != nil {
				logs.Write_log("ERROR", fmt.Sprintf("Connexion échouée: %v", err))
				time.Sleep(30 * time.Second)
				continue
			}

			sto_session.SessionsUser.AddOrUpdate(user, storage.DuckySessionLive.Conn, sessionmgr.SessionPending, storage.DuckySessionLive)

			done := make(chan struct{})
			go func() {
				handleConnection(user, storage.DuckySessionLive)
				close(done)
			}()

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
