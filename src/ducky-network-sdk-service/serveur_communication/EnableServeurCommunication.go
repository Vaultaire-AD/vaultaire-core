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
			// Persistent, et non IsServeur.
			//
			// IsServeur dit « cette machine est un serveur membre du domaine »
			// et vient de client_software.yaml, où l'enrôlement écrit false
			// pour un service. S'en servir pour décider de la reconnexion
			// faisait tourner tout service en mode une-passe : à la première
			// coupure, il sortait de la boucle et ne revenait jamais.
			//
			// Les deux notions n'ont rien à voir : l'une décrit ce qu'est la
			// machine, l'autre ce que le programme doit faire quand le lien
			// tombe.
			if !storage.Persistent {
				// GetBySessionID rend (session, TROUVÉE). La version antérieure
				// nommait ce booléen « err » et testait « == false » : elle
				// supprimait donc la session quand elle était introuvable — en
				// passant un nil — et journalisait une erreur quand tout allait
				// bien. D'où un ERROR à chaque connexion réussie.
				sess, found := stosession.SessionsUser.GetBySessionID(ds.SessionID)
				if found {
					stosession.SessionsUser.FastRemoveSession(sess)
				} else {
					logs.Write_log("DEBUG", "session machine déjà retirée du registre")
				}
				break // Mode une-passe : on ne relance pas la reconnexion.
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
