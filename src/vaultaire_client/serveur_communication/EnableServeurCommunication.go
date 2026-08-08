package serveurcommunication

import (
	"fmt"
	"time"
	"vaultaire_client/logs"
	"vaultaire_client/serveur_communication/module"
	"vaultaire_client/sessionmgr"
	"vaultaire_client/storage"
	"vaultaire_client/storage/stosession"
	sto_session "vaultaire_client/storage/stosession"
)

// Fonction pour gérer la requete au serveur central
func EnableServerCommunication(user, pass string) {
	logs.Print_Log("Launching Vaultaire_Client_Network: " + user)

	if user == "vaultaire" {
		// Dégressivité : le délai double à chaque échec, avec une dispersion
		// aléatoire. Voir backoff.go — l'intervalle fixe de 30 s ramenait tout
		// le parc sur le core au même instant, indéfiniment.
		attente := NewBackoff()

		for {
			var err error
			ds, err := module.EstablishDuckySession(user, pass)
			if err != nil {
				d := attente.Prochain()
				logs.Write_log("ERROR", fmt.Sprintf("Connexion échouée: %v — nouvelle tentative dans %s", err, d))
				time.Sleep(d)
				continue
			}

			// La connexion a abouti : on repart du délai court, sinon une
			// coupure brève après une longue absence coûterait cinq minutes.
			attente.Reset()

			// La session machine "vaultaire" utilise toujours la clé réservée
			// MotherSessionID, quel que soit l'ID généré par défaut à la
			// création : elle doit rester retrouvable à la même clé à travers
			// toutes les reconnexions.
			ds.SessionID = sessionmgr.NewSessionID()
			sto_session.SessionsUser.AddOrUpdate(
				ds.SessionID,
				user,
				ds.Conn,
				sessionmgr.SessionPending,
				ds,
			)

			done := make(chan struct{})
			go func() {
				defer logs.Recover("lecture de la connexion")
				handleConnection(user, ds)
				close(done)
			}()
			if !storage.IsServeur {
				sess, err := stosession.SessionsUser.GetBySessionID(ds.SessionID) // On supprime la session machine dès qu'elle est fermée côté serveur
				if err == false {
					sto_session.SessionsUser.FastRemoveSession(sess)
				} else {
					logs.Write_log("ERROR", "Impossible de récupérer la session machine pour la supprimer")
				}
				break // Mode Client Simple (One-shot) : on ne relance pas la reconnexion
			}
			<-done // Attend la fin de la connexion
			d := attente.Prochain()
			logs.Write_log("WARNING", fmt.Sprintf("Flux arrêté. Reconnexion dans %s...", d))
			time.Sleep(d)
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
		sto_session.SessionsUser.AddOrUpdate(ds.SessionID, user, ds.Conn, sessionmgr.SessionPending, ds)

		handleConnection(user, ds)
	}
}
