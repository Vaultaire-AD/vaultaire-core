package main

import (
	"fmt"
	"log"
	"os"
	"time"
	pamcommunication "vaultaire_client/pam_communication"
	serveurcommunication "vaultaire_client/serveur_communication"
	"vaultaire_client/storage"
	localusermanagement "vaultaire_client/tools/local_user_management"
	yaml_vaultaire "vaultaire_client/yaml"

	"gopkg.in/yaml.v2"
)

type config struct {
	ServerListenPort string `yaml:"serveurlistenport"`
	ServerIP         string `yaml:"serveur_ip"`
}

func StartDailyUserCleanup() {
	go func() {
		for {
			now := time.Now()
			next := time.Date(now.Year(), now.Month(), now.Day(), 6, 0, 0, 0, now.Location())

			if now.After(next) {
				next = next.Add(24 * time.Hour)
			}

			duration := time.Until(next)
			log.Printf("⏳ Prochaine exécution de la suppression à %s", next.Format(time.RFC1123))

			time.Sleep(duration)

			log.Println("🚀 Lancement de la suppression des utilisateurs Vaultaire inactifs")
			localusermanagement.DeleteUser_Vaultaire_Past_4Days_withoutconnection()

			time.Sleep(24 * time.Hour)
		}
	}()
}

func loadConfig(filePath string) error {
	// Ouvrir le fichier
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer func() {
		if err := file.Close(); err != nil {
			// Handle or log the error
			fmt.Printf("erreur lors de la fermeture du fichier: %v", err)
		}
	}()

	// Initialiser une variable pour stocker les données du fichier
	var config config

	// Décoder le fichier YAML dans la structure Config
	decoder := yaml.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		return err
	}
	storage.C_serveurIP = config.ServerIP
	storage.C_serveurListenPort = config.ServerListenPort
	// Retourner la configuration lue
	return nil
}

func main() {
	err := loadConfig("/opt/vaultaire_client/client_conf.yaml")
	if err != nil {
		log.Fatalf("Erreur lors de la lecture du fichier de configuration : %v", err)

	}
	yaml_vaultaire.ReadYAMLFile(storage.SoftwarePath)
	log.SetOutput(os.Stdout)
	StartDailyUserCleanup()
	// Lancer le serveur de socket Unix
	if storage.IsServeur {
		go serveurcommunication.EnableServerCommunication("vaultaire", "vaultaire")
	}
	pamcommunication.UnixSocketServer()
}
