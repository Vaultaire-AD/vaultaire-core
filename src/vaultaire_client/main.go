package main

import (
	duckytool "duckynetworkclient/V1/duckynetwork/ducky_tool"
	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/storage"
	tramesmanager "duckynetworkclient/V1/duckynetwork/trames_manager"
	"flag"
	"fmt"
	"log"
	"os"
	"time"
	"vaultaire_client/config"
	"vaultaire_client/gpo"
	pamcommunication "vaultaire_client/pam_communication"
	"vaultaire_client/revocation"
	serveurcommunication "vaultaire_client/serveur_communication"
	"vaultaire_client/sshauth"
	"vaultaire_client/tools"
	localusermanagement "vaultaire_client/tools/local_user_management"
	yaml_vaultaire "vaultaire_client/yaml"
)

func StartDailyUserCleanup() {
	go func() {
		defer logs.Recover("tache de fond")
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

// brancherSocleDucky raccorde l'agent au socle partagé.
//
// À appeler EN PREMIER dans main, avant toute ouverture de session : la boucle
// de réception consulte le registre des gestionnaires dès la connexion établie,
// et une catégorie branchée après coup laisserait passer sans traitement les
// trames arrivées entre-temps.
func brancherSocleDucky() {
	// L'agent reste connecté. Persistent et non IsServeur : ce dernier décrit
	// la MACHINE — serveur membre du domaine — et vient de client_software.yaml,
	// où il vaut false pour un poste ordinaire. S'en servir pour décider de la
	// reconnexion faisait sortir de la boucle à la première coupure.
	storage.Persistent = true

	// La boucle de connexion de l'agent, et non celle du socle : elle lit
	// /etc/vaultaire_client/client_conf.json, au format JSON déjà déployé sur
	// le parc, là où le socle attend du YAML.
	duckytool.DemarrerSessionMachine = func() {
		serveurcommunication.EnableServerCommunication("vaultaire", "vaultaire")
	}

	// Les catégories propres à l'agent. 01 et 02 sont fournies par le socle :
	// 01 est lue de façon synchrone avant que la boucle ne démarre, 02 est
	// branchée par le socle lui-même.
	tramesmanager.RegisterHandler("03", sshauth.HandleTrameSSH)
	tramesmanager.RegisterHandler("05", gpo.HandleTrameGPO)
	tramesmanager.RegisterHandler("06", revocation.HandleTrameRevocation)
}

func main() {
	brancherSocleDucky()

	// ... chargement config ...
	err := config.LoadConfig("/etc/vaultaire_client/client_conf.json")
	if err != nil {
		log.Fatalf("Erreur lors de la lecture du fichier de configuration : %v", err)

	}
	yaml_vaultaire.ReadYAMLFile(storage.SoftwarePathResolu())

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
		logs.Go("communication serveur", func() {
			serveurcommunication.EnableServerCommunication("vaultaire", "vaultaire")
		})
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
				logs.Go("communication serveur", func() {
					serveurcommunication.EnableServerCommunication("vaultaire", "vaultaire")
				})
			}
		}

		// Transport des GPO. Le comportement est identique pour un client
		// serveur et un client poste : seule la liste des groupes diffère côté
		// serveur. Le premier cycle attend qu'une session mère soit disponible,
		// donc l'appel n'a pas à être ordonné avec l'ouverture du tunnel.
		gpo.Bootstrap()

		// Le service d'allocation d'identifiants AVANT le canal PAM.
		//
		// UnixSocketServer bloque : tout ce qui doit vivre à côté se lance avant.
		//
		// Ce service répond au module NSS pour un utilisateur du domaine encore
		// inconnu. Sans lui, sshd refuse le compte avant même d'exécuter
		// AuthorizedKeysCommand, et aucune première connexion n'est possible —
		// sans la moindre trace, puisque rien de Vaultaire n'est exécuté.
		pamcommunication.StartUIDAllocationServer()

		pamcommunication.UnixSocketServer()
	}

}
