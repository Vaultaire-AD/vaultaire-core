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
)

// Fonction pour gérer la requete au serveur central

func HaveServeurKey() bool {
	serveurKeyPath := filepath.Join(storage.KeyPath, "serveurpublickey.pem")
	_, privateErr := os.Stat(serveurKeyPath)
	return !os.IsNotExist(privateErr)
}

func EnableServerCommunication(user, pass, sshUser string) {
	fmt.Printf("Launching Vaultaire_Client_Network: %s\n", user)
	if user == "vaultaire" {
		for {
			serverAddr := storage.C_serveurIP + ":" + storage.C_serveurListenPort
			conn, err := net.Dial("tcp", serverAddr)
			if err != nil {
				logs.Write_log("ERROR", fmt.Sprintf("Erreur lors de la connexion au serveur : %v", err))
				time.Sleep(30 * time.Second)
				continue
			}
			storage.SessionsUser.AddOrUpdate(
				user,
				conn,
				sessionmgr.SessionPending,
			)
			var duckysession storage.DuckySession
			duckysession.Conn = conn
			duckysession.IsSafe = false
			if !HaveServeurKey() {
				_ = serveur.AskServerKey(&duckysession)
			}
			duckysession.SessionKey = serveur.AskServerAuthentification(&duckysession)

			// Lance le gestionnaire de connexion en goroutine
			done := make(chan struct{})
			go func() {
				handleConnection(user, &duckysession)
				close(done) // signal que handleConnection est terminé
			}()

			// Lance l'authentification (si c'est bloquant, c'est ok)
			userauth.AskAuthentification(user, pass, &duckysession)

			if sshUser != "" {
				logs.Write_log("INFO", fmt.Sprintf("Attente fin de check ssh pour l'utilisateur : %s", sshUser))

				for {
					status, ok := storage.SessionsUser.GetStatus(user)
					if !ok {
						logs.Write_log("ERROR", "Session disparue")
						break
					}
					sessionIntegritykey := string(duckysession.SessionKey)
					if status == sessionmgr.SessionAuthenticated {
						logs.Write_log("INFO", fmt.Sprintf("Session authentifiée pour l'utilisateur : %s, demande des clés SSH pour", sshUser))
						msg := "03_01\nserveur_central\n" +
							sessionIntegritykey + "\n" +
							user + "\n" +
							storage.Computeur_ID + "\n" +
							"ask_sshpubkey\n" +
							sshUser

						sendmessage.SendMessage(msg, &duckysession)
						break
					}

					if status == sessionmgr.SessionFailed {
						logs.Write_log("ERROR", "Auth échouée, abandon")
						break
					}

					time.Sleep(100 * time.Millisecond)
				}
			}
			// Attendre que la connexion soit terminée avant de continuer
			<-done
			logs.Write_log("INFO", "Connexion terminée, nouvelle tentative dans 30 secondes...")
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
