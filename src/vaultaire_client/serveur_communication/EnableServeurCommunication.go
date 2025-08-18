package serveurcommunication

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
	serveur "vaultaire_client/duckynetworkClient/serveurauth"
	"vaultaire_client/duckynetworkClient/userauth"
	"vaultaire_client/storage"
)

// Fonction pour gérer la requete au serveur central

func HaveServeurKey() bool {
	serveurKeyPath := filepath.Join(storage.KeyPath, "serveurpublickey.pem")
	_, privateErr := os.Stat(serveurKeyPath)
	return !os.IsNotExist(privateErr)
}

func EnableServerCommunication(user, pass string) {
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
