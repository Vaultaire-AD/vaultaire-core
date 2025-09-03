package main

import (
	configurationfile "DUCKY/serveur/configuration_file"
	db "DUCKY/serveur/database"
	"DUCKY/serveur/dns"
	duckynetwork "DUCKY/serveur/ducky-network"
	ldap "DUCKY/serveur/ldap"
	"DUCKY/serveur/storage"
	"DUCKY/serveur/vaultairegoroutine"
	webserveur "DUCKY/serveur/web_serveur"
	"log"
	"net"
)

type ClientInfo struct {
	IP   string
	Conn net.Conn
}

func main() {
	err := configurationfile.LoadConfig("/opt/vaultaire/serveur_conf.yaml")
	if err != nil {
		log.Fatalf("Erreur lors de la lecture du fichier de configuration : %v", err)
	}
	db.InitDatabase()
	db.Create_DataBase(db.GetDatabase())
	go duckynetwork.StartDuckyServer()

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
	if storage.API_Enable {
		go vaultairegoroutine.StartAPI()
	} else {
		log.Println("API is disabled, not starting API server.")
	}

	vaultairegoroutine.StartUnixSocketServer()
	// go ldap.HandleLDAPserveur()

}
