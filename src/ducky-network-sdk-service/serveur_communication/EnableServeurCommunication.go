package serveurcommunication

import (
	"fmt"

	"duckynetworkclient/V1/backoff"
	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/storage"
	"duckynetworkclient/V1/duckynetwork/storage/stosession"
	"duckynetworkclient/V1/serveur_communication/module"
	"duckynetworkclient/V1/sessionmgr"
	"time"
)

// EnableServerCommunication ouvre la session Ducky et la maintient.
//
// # Deux régimes
//
//	Persistent  : reconnexion sans fin, avec dégressivité
//	sinon       : une passe, puis retour à l'appelant
//
// Le second sert aux utilitaires qui font une chose et sortent. Le premier est
// celui de tout ce qui doit rester joignable — agent, proxy, service.
func EnableServerCommunication(user, pass string) {
	logs.Print_Log("Launching Vaultaire_Client_Network: " + user)

	if user == "vaultaire" {
		// Dégressivité plutôt qu'un intervalle fixe.
		//
		// À 30 secondes fixes, un core qui redémarre voit revenir TOUT le parc
		// au même instant, toutes les 30 secondes, chaque connexion réclamant
		// une poignée de main RSA-4096. La charge de reprise devient alors le
		// problème suivant, et elle se répète tant que le core n'a pas tenu.
		// Voir backoff/backoff.go, notamment la dispersion aléatoire — c'est
		// elle qui empêche mille agents de rester synchronisés.
		attente := backoff.New()

		for {
			ds, err := module.EstablishDuckySession(user, pass)
			if err != nil {
				d := attente.Prochain()
				logs.Write_log("ERROR", fmt.Sprintf(
					"Connexion échouée: %v — nouvelle tentative dans %s", err, d))
				time.Sleep(d)
				continue
			}

			// La connexion a abouti : on repart du délai court, sinon une
			// coupure brève après une longue absence coûterait le délai
			// maximal.
			attente.Reset()

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
				// Une panique dans la lecture de la connexion tuerait tout le
				// processus, pas seulement cette goroutine — donc l'agent
				// entier, canal PAM compris, sur une trame malformée.
				defer logs.Recover("lecture de la connexion")
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
				// GetBySessionID rend (session, TROUVÉE). Une version
				// antérieure nommait ce booléen « err » et testait
				// « == false » : elle supprimait donc la session quand elle
				// était introuvable — en passant un zéro — et journalisait une
				// erreur quand tout allait bien. D'où un ERROR à chaque
				// connexion réussie.
				sess, found := stosession.SessionsUser.GetBySessionID(ds.SessionID)
				if found {
					stosession.SessionsUser.FastRemoveSession(sess)
				} else {
					logs.Write_log("DEBUG", "session machine déjà retirée du registre")
				}
				break // Mode une-passe : on ne relance pas la reconnexion.
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
		stosession.SessionsUser.AddOrUpdate(ds.SessionID, user, ds.Conn, sessionmgr.SessionPending, ds)

		handleConnection(user, ds)
	}
}
