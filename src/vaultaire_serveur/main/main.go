package main

import (
	"log"
	"net"
	"os"

	configurationfile "vaultaire/serveur/configuration_file"
	db "vaultaire/serveur/database"
	"vaultaire/serveur/dns"
	duckynetwork "vaultaire/serveur/ducky-network"
	ldap "vaultaire/serveur/ldap"
	"vaultaire/serveur/logs"
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
		logs.Write_Log("INFO", "bootstrap: default administrator disabled")
	}

	if storage.Ldap_Enable {
		go ldap.HandleLDAPserveur()
	} else {
		logs.Write_Log("INFO", "ldap: server disabled, not starting")
	}
	if condition := storage.Ldaps_Enable; condition {
		go ldap.HandleLDAPSserveur()
	} else {
		logs.Write_Log("INFO", "ldaps: server disabled, not starting")
	}
	if storage.Website_Enable {
		go webserveur.StartWebServer()
	} else {
		logs.Write_Log("INFO", "website: server disabled, not starting")
	}
	if storage.Dns_Enable {
		go dns.DNS_StartServeur()
	}
	if storage.API_Enable {
		logs.Write_Log("INFO", "api: starting REST server")
		go vaultairegoroutine.StartAPI()
	} else {
		logs.Write_Log("INFO", "api: server disabled, not starting")
	}

	vaultairegoroutine.StartUnixSocketServer()
	// go ldap.HandleLDAPserveur()

}
