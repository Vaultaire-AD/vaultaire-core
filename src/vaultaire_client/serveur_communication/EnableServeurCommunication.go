package serveurcommunication

import (
	"fmt"
	"time"

	"duckynetworkclient/V1/backoff"
	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/storage"
	"duckynetworkclient/V1/duckynetwork/storage/stosession"
	"duckynetworkclient/V1/sessionmgr"
	"vaultaire_client/serveur_communication/module"
)

// Fonction pour gérer la requete au serveur central
func EnableServerCommunication(user, pass string) {
	logs.Print_Log("Launching Vaultaire_Client_Network: " + user)

	if user == "vaultaire" {
		// Dégressivité : le délai double à chaque échec, avec une dispersion
		// aléatoire. Le paquet a rejoint le socle — voir backoff/backoff.go —
		// pour que le proxy et les services en profitent : ils avaient le même
		// intervalle fixe de 30 s, qui ramène tout le parc sur le core au même
		// instant, indéfiniment.
		attente := backoff.New()

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
			stosession.SessionsUser.AddOrUpdate(
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
			// Persistent, et non IsServeur.
			//
			// IsServeur dit « cette machine est un serveur membre du domaine »
			// et vient de client_software.yaml, où il vaut false pour un poste
			// ordinaire. S'en servir pour décider de la reconnexion faisait
			// sortir de la boucle à la première coupure sur tout poste non
			// serveur — et ne plus jamais revenir.
			//
			// Les deux notions n'ont rien à voir : l'une décrit ce qu'EST la
			// machine, l'autre ce que le programme doit FAIRE quand le lien
			// tombe. brancherSocleDucky pose Persistent = true dans main.
			if !storage.Persistent {
				// GetBySessionID rend (session, TROUVÉE).
				//
				// Le booléen était nommé « err » et testé « == false » : la
				// session était donc supprimée quand elle était INTROUVABLE —
				// en passant une valeur nulle — et une ERREUR journalisée
				// quand tout allait bien. D'où un ERROR à chaque connexion
				// réussie, qui a longtemps fait chercher au mauvais endroit.
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
