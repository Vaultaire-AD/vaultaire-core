package main

import (
	"log"
	"net"
	"os"

	"vaultaire/cluster"
	configurationfile "vaultaire/core/configuration_file"
	db "vaultaire/core/database"
	dbauthpolicy "vaultaire/core/database/db_authpolicy"
	dbgpo "vaultaire/core/database/db_gpo"
	dbrevocation "vaultaire/core/database/db_revocation"
	"vaultaire/core/dns"
	ldap "vaultaire/core/ldap"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
	"vaultaire/core/storage"
	"vaultaire/core/testrunner"
	"vaultaire/core/vaultairegoroutine"
	webserveur "vaultaire/core/web_serveur"
	duckynetwork "vaultaire/ducky-network"
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

	// Le schéma GPO est créé après les tables de base (gpo_group référence
	// groups) et par son propre package, qui détient aussi la suppression des
	// tables de l'ancien modèle.
	if err := dbgpo.CreateTables(db.GetDatabase()); err != nil {
		log.Fatalf("Erreur lors de la création du schéma GPO : %v", err)
	}

	// Schéma du kill switch, puis branchement du vérificateur de révocation.
	//
	// L'inversion de dépendance évite un cycle : core/permission ne peut pas
	// importer db_revocation, qui dépend lui-même de la validation des
	// identifiants. C'est main, qui voit les deux, qui fait la liaison.
	//
	// L'ordre compte : tant que ce branchement n'a pas eu lieu, aucun compte
	// n'est considéré comme révoqué. Il doit donc précéder le démarrage de tout
	// service acceptant des connexions.
	if err := dbrevocation.CreateTables(db.GetDatabase()); err != nil {
		log.Fatalf("Erreur lors de la création du schéma de révocation : %v", err)
	}
	permission.SetRevokedChecker(func(username string) bool {
		return dbrevocation.IsRevoked(db.GetDatabase(), username)
	})

	// Second facteur et expiration des mots de passe.
	//
	// Après Create_DataBase, dont ce schéma étend les tables `users` et
	// `groups` : les colonnes ne peuvent être ajoutées qu'à des tables déjà
	// créées. Et avant tout service acceptant des connexions, pour qu'aucune
	// authentification n'ait lieu sur un schéma à moitié posé.
	if err := dbauthpolicy.CreateSchema(db.GetDatabase()); err != nil {
		log.Fatalf("Erreur lors de la création du schéma d'authentification : %v", err)
	}

	// La permission d'amorçage reçoit toutes les actions connues du code, pas
	// une liste recopiée dans du SQL. Passe à chaque démarrage, en INSERT
	// IGNORE : les bases existantes récupèrent ainsi les clés apparues depuis
	// leur création, sans script de migration.
	if err := db.EnsureSuperadminActions(db.GetDatabase(), permission.AllActionKeys()); err != nil {
		logs.Write_Log("ERROR", "bootstrap: actions du groupe superadmin non accordées : "+err.Error())
	}

	cluster.StartManager(db.GetDatabase())
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
