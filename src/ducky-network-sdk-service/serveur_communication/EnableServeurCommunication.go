package serveurcommunication

import (
	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/storage"
	"duckynetworkclient/V1/duckynetwork/storage/stosession"
	"duckynetworkclient/V1/serveur_communication/module"
	"duckynetworkclient/V1/sessionmgr"
	"fmt"
	"time"
)

// Fonction pour gérer la requete au serveur central
func EnableServerCommunication(user, pass string) {
	logs.Print_Log("Launching Vaultaire_Client_Network: " + user)

	if user == "vaultaire" {
		for {
			var err error
			ds, err := module.EstablishDuckySession(user, pass)
			if err != nil {
				logs.Write_log("ERROR", fmt.Sprintf("Connexion échouée: %v", err))
				time.Sleep(30 * time.Second)
				continue
			}

			// La session machine "vaultaire" utilise toujours la clé réservée
			// MotherSessionID, quel que soit l'ID généré par défaut à la
			// création : elle doit rester retrouvable à la même clé à travers
			// toutes les reconnexions.
			ds.SessionID = sessionmgr.NewSessionID()
			stosession.SessionsUser.AddOrUpdate(
				ds.SessionID,
				user,
				ds.Conn,
				sessionmgr.SessionPending,
				ds,
			)

			done := make(chan struct{})
			go func() {
				handleConnection(user, ds)
				close(done)
			}()
			if !storage.IsServeur {
				sess, err := stosession.SessionsUser.GetBySessionID(ds.SessionID) // On supprime la session machine dès qu'elle est fermée côté serveur
				if err == false {
					stosession.SessionsUser.FastRemoveSession(sess)
				} else {
					logs.Write_log("ERROR", "Impossible de récupérer la session machine pour la supprimer")
				}
				break // Mode Client Simple (One-shot) : on ne relance pas la reconnexion
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

		// Important : jusqu'ici ces sessions PAM n'étaient jamais
		// enregistrées dans SessionsUser, donc introuvables ensuite (ex :
		// PamClose ne trouvait jamais la session à fermer). On l'enregistre
		// dès la création, avec son propre SessionID (distinct de "1", qui
		// est réservé à la session machine).
		stosession.SessionsUser.AddOrUpdate(ds.SessionID, user, ds.Conn, sessionmgr.SessionPending, ds)

		handleConnection(user, ds)
	}
}
