package main

import (
	"fmt"
	"log"
	"net"
	"os"

	configurationfile "vaultaire/serveur/configuration_file"
	db "vaultaire/serveur/database"
	"vaultaire/serveur/dns"
	duckynetwork "vaultaire/serveur/ducky-network"
	ldap "vaultaire/serveur/ldap"
	"vaultaire/serveur/storage"
	"vaultaire/serveur/testrunner"
	"vaultaire/serveur/vaultairegoroutine"
	webserveur "vaultaire/serveur/web_serveur"
)

type ClientInfo struct {
	IP   string
	Conn net.Conn
}

func main() {
	for _, arg := range os.Args[1:] {
		if arg == "--test" {
			os.Exit(testrunner.RunFromMain())
		}
	}

	err := configurationfile.LoadConfig("/opt/vaultaire/serveur_conf.yaml")
	if err != nil {
		log.Fatalf("Erreur lors de la lecture du fichier de configuration : %v", err)
	}

	db.InitDatabase()
	db.Create_DataBase(db.GetDatabase())
	go duckynetwork.StartDuckyServer()

	if storage.Administrateur_Enable {
		db.CreateDefaultAdminUser(db.GetDatabase())
	} else {
		log.Println("[BOOTSTRAP] Default Administrateur désactivé")
	}

	if storage.Ldap_Enable {
		go ldap.HandleLDAPserveur()
	} else {
		log.Println("LDAP is disabled, not starting LDAP server.")
	}
	if condition := storage.Ldaps_Enable; condition {
		go ldap.HandleLDAPSserveur()
	} else {
		log.Println("LDAPS is disabled, not starting LDAPS server.")

	}
	if storage.Website_Enable {
		go webserveur.StartWebServer()
	} else {
		log.Println("Website is disabled, not starting web server.")
	}
	if storage.Dns_Enable {
		go dns.DNS_StartServeur()
	}
	fmt.Printf("DEBUG: storage.API_Enable = %v", storage.API_Enable)
	if storage.API_Enable {
		log.Println("API TRY TO START")
		go vaultairegoroutine.StartAPI()
	} else {
		log.Println("API is disabled, not starting API server.")
	}

	vaultairegoroutine.StartUnixSocketServer()
	// go ldap.HandleLDAPserveur()

}
