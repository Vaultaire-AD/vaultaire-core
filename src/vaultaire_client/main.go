package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"
	"vaultaire_client/config"
	"vaultaire_client/logs"
	pamcommunication "vaultaire_client/pam_communication"
	serveurcommunication "vaultaire_client/serveur_communication"
	"vaultaire_client/storage"
	"vaultaire_client/tools"
	localusermanagement "vaultaire_client/tools/local_user_management"
	yaml_vaultaire "vaultaire_client/yaml"
)

func StartDailyUserCleanup() {
	go func() {
		for {
			now := time.Now()
			next := time.Date(now.Year(), now.Month(), now.Day(), 6, 0, 0, 0, now.Location())

			if now.After(next) {
				next = next.Add(24 * time.Hour)
			}

			duration := time.Until(next)
			logs.Write_log("INFO", fmt.Sprintf("⏳ Prochaine exécution de la suppression à %s", next.Format(time.RFC1123)))

			time.Sleep(duration)
			logs.Write_log("INFO", "🚀 Lancement de la suppression des utilisateurs Vaultaire inactifs")
			localusermanagement.DeleteUser_Vaultaire_Past_4Days_withoutconnection()

			time.Sleep(24 * time.Hour)
		}
	}()
}

func main() {
	// ... chargement config ...
	err := config.LoadConfig("/etc/vaultaire_client/client_conf.json")
	if err != nil {
		log.Fatalf("Erreur lors de la lecture du fichier de configuration : %v", err)

	}
	yaml_vaultaire.ReadYAMLFile(storage.SoftwarePath)

	fetchKey := flag.String("fetch-key", "", "Récupère les clés publiques pour SSH")
	flag.Parse()
	if *fetchKey != "" {
		sshUser := *fetchKey
		_, domain := tools.ExctractDomainFromUsername(sshUser)
		if domain == "" { // fonction équivalente à vaultaire_is_allowed_domain côté C
			logs.Write_log("DEBUG", "Fetch-key ignoré (user local, pas de domaine Vaultaire): "+sshUser)
			return
		}
		storage.SilentConsole = true
		// Mode One-Shot pour SSH
		go serveurcommunication.EnableServerCommunication("vaultaire", "vaultaire")
		serveurcommunication.WaitForSSHFetch("vaultaire", sshUser)
		// 🔥 AJOUTE CECI :
		logs.Write_log("INFO", "Fin du mode Fetch, fermeture du programme.")
		os.Exit(0) // On force l'arrêt propre du binaire
	} else {
		StartDailyUserCleanup()
		// Lancer le serveur de socket Unix
		if storage.IsServeur {
			// 3. Appel vers le serveur backend Vaultaire
			if tools.IsDuckySessionActive() {

			} else {
				go serveurcommunication.EnableServerCommunication("vaultaire", "vaultaire")
			}
		}
		pamcommunication.UnixSocketServer()
	}

}
