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
				fmt.Println("Erreur lors de la connexion au serveur :", err)
				time.Sleep(30 * time.Second)
				continue
			}
			storage.SessionsUser.AddOrUpdate(
				user,
				conn,
				sessionmgr.SessionPending,
			)

			if !HaveServeurKey() {
				_ = serveur.AskServerKey(conn)
			}
			sessionIntegritykey := serveur.AskServerAuthentification(conn)

			// Lance le gestionnaire de connexion en goroutine
			done := make(chan struct{})
			go func() {
				handleConnection(user, conn)
				close(done) // signal que handleConnection est terminé
			}()

			// Lance l'authentification (si c'est bloquant, c'est ok)
			userauth.AskAuthentification(user, pass, conn, sessionIntegritykey)

			if sshUser != "" {
				fmt.Println("Attente fin d'auth pour :", sshUser)

				for {
					status, ok := storage.SessionsUser.GetStatus(user)
					if !ok {
						fmt.Println("Session disparue")
						break
					}

					if status == sessionmgr.SessionAuthenticated {
						fmt.Println("Session authentifiée, envoi 03_01")

						msg := "03_01\nserveur_central\n" +
							sessionIntegritykey + "\n" +
							user + "\n" +
							storage.Computeur_ID + "\n" +
							"ask_sshpubkey\n" +
							sshUser

						sendmessage.SendMessage(msg, conn)
						break
					}

					if status == sessionmgr.SessionFailed {
						fmt.Println("Auth échouée, abandon")
						break
					}

					time.Sleep(100 * time.Millisecond)
				}
			}
			// Attendre que la connexion soit terminée avant de continuer
			<-done
			fmt.Println("Connexion terminée, nouvelle tentative dans 30 secondes...")
			time.Sleep(30 * time.Second)
		}
	} else {
		serverAddr := storage.C_serveurIP + ":" + storage.C_serveurListenPort
		conn, err := net.Dial("tcp", serverAddr)
		if err != nil {
			fmt.Println("Erreur lors de la connexion au serveur :", err)
			return
		}
		// Exemple simplifié de logique liée au serveur
		if !HaveServeurKey() {
			_ = serveur.AskServerKey(conn)
		}
		sessionIntegritykey := serveur.AskServerAuthentification(conn)
		go handleConnection(user, conn)
		userauth.AskAuthentification(user, pass, conn, sessionIntegritykey)
	}
}
