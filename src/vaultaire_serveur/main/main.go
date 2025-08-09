package main

import (
	configurationfile "DUCKY/serveur/configuration_file"
	db "DUCKY/serveur/database"
	"DUCKY/serveur/database/sync"
	"DUCKY/serveur/dns"
	keymanagement "DUCKY/serveur/key_management"
	ldap "DUCKY/serveur/ldap"
	"DUCKY/serveur/logs"
	"DUCKY/serveur/storage"
	"DUCKY/serveur/vaultairegoroutine"
	webserveur "DUCKY/serveur/web_serveur"
	"fmt"
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
	sync.Sync_InitMapDuckyIntegrity()
	go vaultairegoroutine.ClearSession()
	go vaultairegoroutine.StartUnixSocketServer()
	// go ldap.HandleLDAPserveur()
	go vaultairegoroutine.CheckServeurOnline()
	err = keymanagement.Generate_Serveur_Key_Pair()
	if err != nil {
		fmt.Println("Error For generate Server Key:", err)
		logs.Write_Log("CRITICAL", "Error For generate Server Key: "+err.Error())
	}
	err = keymanagement.Generate_SSH_Key_For_Login_Client()
	if err != nil {
		fmt.Println("Error For generate SSH Key:", err)
		logs.Write_Log("CRITICAL", "Error For generate SSH Key: "+err.Error())
	}
	listener, err := net.Listen("tcp", ":"+storage.ServeurLisetenPort)
	if err != nil {
		fmt.Println("Erreur lors de l'écoute sur le port : "+storage.ServeurLisetenPort, err)
		logs.Write_Log("CRITICAL", "Error For listening on Port : "+storage.ServeurLisetenPort+" "+err.Error())
		return
	}
	fmt.Println("Server Is ready and lsiten on port " + storage.ServeurLisetenPort + " ...")
	logs.Write_Log("INFO", "Server Is ready and lsiten on port "+storage.ServeurLisetenPort+" ...")
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error For Accept New Connection :", err)
			logs.Write_Log("WARNING", "Error For Accept New Connection: "+err.Error())
			continue
		}
		go vaultairegoroutine.HandleConnection(conn)
	}
}
