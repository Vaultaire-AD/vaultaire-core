package serveurcommunication

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
	"vaultaire_client/duckynetworkClient/sendmessage"
	serveur "vaultaire_client/duckynetworkClient/serveurauth"
	"vaultaire_client/duckynetworkClient/userauth"
	"vaultaire_client/logs"
	"vaultaire_client/sessionmgr"
	"vaultaire_client/storage"
	sto_session "vaultaire_client/storage/stosession"
)

// Fonction pour gérer la requete au serveur central

func HaveServeurKey() bool {
	serveurKeyPath := filepath.Join(storage.KeyPath, "serveurpublickey.pem")
	_, privateErr := os.Stat(serveurKeyPath)
	return !os.IsNotExist(privateErr)
}

func EnableServerCommunication(user, pass, sshUser string, sshpassword *string) {
	fmt.Printf("Launching Vaultaire_Client_Network: %s\n", user)
	if user == "vaultaire" {
		for {
			serverAddr := storage.C_serveurIP + ":" + storage.C_serveurListenPort
			logs.Write_log("INFO", fmt.Sprintf("Tentative de connexion au serveur central: %s", serverAddr))

			conn, err := net.DialTimeout("tcp", serverAddr, 10*time.Second)
			if err != nil {
				logs.Write_log("ERROR", fmt.Sprintf("Erreur lors de la connexion au serveur : %v", err))
				time.Sleep(30 * time.Second)
				continue
			}

			var duckysession storage.DuckySession
			duckysession.Conn = conn
			duckysession.IsSafe = false

			sto_session.SessionsUser.AddOrUpdate(user, conn, sessionmgr.SessionPending, &duckysession)

			if !HaveServeurKey() {
				logs.Write_log("INFO", "Clé serveur manquante, demande en cours...")
				_ = serveur.AskServerKey(&duckysession)
			}

			duckysession.SessionKey = serveur.AskServerAuthentification(&duckysession)

			done := make(chan struct{})
			go func() {
				handleConnection(user, &duckysession)
				close(done)
			}()

			userauth.AskAuthentification(user, pass, &duckysession)

			if sshUser != "" && sshpassword != nil && *sshpassword != "" {
				logs.Write_log("INFO", fmt.Sprintf("Attente authentification pour requete SSH (%s)", sshUser))

				// On sortira de ce for si status == Authenticated, Failed, ou si la session est supprimée
				for {
					status, ok := sto_session.SessionsUser.GetStatus(user)
					if !ok {
						logs.Write_log("ERROR", "La session a été nettoyée par le manager pendant l'auth")
						break
					}

					sessionIntegritykey := string(duckysession.SessionKey)
					if status == sessionmgr.SessionAuthenticated {
						logs.Write_log("INFO", fmt.Sprintf("Session OK, envoi demande SSH pour %s", sshUser))

						msg := fmt.Sprintf("03_01\nserveur_central\n%s\n%s\n%s\nask_sshpubkey\n%s\n%s",
							sessionIntegritykey, user, storage.Computeur_ID, sshUser, *sshpassword)

						sendmessage.SendMessage(msg, &duckysession)
						msg = ""
						break
					}

					if status == sessionmgr.SessionFailed {
						logs.Write_log("ERROR", "Authentification rejetée par le serveur")
						break
					}

					time.Sleep(200 * time.Millisecond)
				}
			}

			// Ici, on attend que handleConnection rende la main (erreur réseau ou fermeture)
			<-done
			logs.Write_log("WARNING", "Le flux réseau s'est arrêté. Relance de la procédure dans 30s...")
			time.Sleep(30 * time.Second)
		}
	} else {
		serverAddr := storage.C_serveurIP + ":" + storage.C_serveurListenPort
		conn, err := net.Dial("tcp", serverAddr)
		if err != nil {
			logs.Write_log("ERROR", fmt.Sprintf("Erreur lors de la connexion au serveur : %v", err))
			return
		}
		var duckysession storage.DuckySession
		duckysession.Conn = conn
		duckysession.IsSafe = false
		// Exemple simplifié de logique liée au serveur
		if !HaveServeurKey() {
			_ = serveur.AskServerKey(&duckysession)
		}
		duckysession.SessionKey = serveur.AskServerAuthentification(&duckysession)
		go handleConnection(user, &duckysession)
		userauth.AskAuthentification(user, pass, &duckysession)
	}
}
