package main

import (
	"log"
	"net"
	"os"

	dbschema "vaultaire/core/database/db_schema"

	"vaultaire/cluster"
	"vaultaire/core/action"
	commandcertificate "vaultaire/core/command/command_certificate"
	configurationfile "vaultaire/core/configuration_file"
	db "vaultaire/core/database"
	dbauthpolicy "vaultaire/core/database/db_authpolicy"
	dbenrollment "vaultaire/core/database/db_enrollment"
	dbgpo "vaultaire/core/database/db_gpo"
	dbrevocation "vaultaire/core/database/db_revocation"
	"vaultaire/core/dns"
	ldap "vaultaire/core/ldap"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
	"vaultaire/core/reglages"
	"vaultaire/core/storage"
	"vaultaire/core/testrunner"
	"vaultaire/core/vaultairegoroutine"
	webserveur "vaultaire/core/web_serveur"
	duckynetwork "vaultaire/ducky-network"
	hosthandler "vaultaire/ducky-network/host_handler"
)

type ClientInfo struct {
	IP   string
	Conn net.Conn
}

// La période de balayage des services vit désormais en base, sous la clé
// « service_sweep_seconds » — voir core/reglages. Elle valait une minute en dur
// et ne pouvait changer qu'à la recompilation.
//
// La contrainte reste écrite avec le réglage : elle doit rester INFÉRIEURE au
// seuil de péremption d'un battement de cœur, sinon un service tombé reste
// affiché en ligne pendant près de deux fois ce seuil.

func main() {
	for _, arg := range os.Args[1:] {
		if arg == "--test" {
			os.Exit(testrunner.RunFromMain())
		}
	}

	// Garnissage du catalogue d'actions, AVANT tout service.
	//
	// Sans cet appel, le catalogue reste vide et chaque action — ligne de
	// commande comme interface web — échoue sur « action inconnue ». Le
	// serveur démarre pourtant sans un mot : rien, dans un catalogue vide, ne
	// distingue « pas encore garni » de « rien à garnir ».
	//
	// L'appel est explicite et non un init() : l'ordre d'initialisation entre
	// paquets dépendrait sinon de l'ordre des imports, et un import retiré
	// ferait disparaître des actions sans la moindre erreur de compilation.
	// Voir action.EnregistrerTout.
	action.EnregistrerTout()

	// Raccordement de la régénération de certificat.
	//
	// L'action certificate.regenerate porte la clé et la portée ; l'exécution
	// vit dans commandcertificate, qui importe déjà le registre. L'inversion
	// évite le cycle — même motif que permission.SetRevokedChecker.
	commandcertificate.BrancherRegeneration()

	err := configurationfile.LoadConfig("/opt/vaultaire/serveur_conf.yaml")
	if err != nil {
		log.Fatalf("Erreur lors de la lecture du fichier de configuration : %v", err)
	}

	db.InitDatabase()
	dbschema.Create_DataBase(db.GetDatabase())

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

	// Clés d'enrôlement des clients service.
	//
	// Avant tout service acceptant des connexions : un service qui tenterait de
	// s'enrôler avant que la table existe recevrait un refus serveur, alors que
	// sa clé est valide.
	if err := dbenrollment.CreateTables(db.GetDatabase()); err != nil {
		log.Fatalf("Erreur lors de la création du schéma d'enrôlement : %v", err)
	}

	// Balayage des services qui ne battent plus.
	//
	// Le passage hors ligne est écrit par le serveur plutôt que déduit à la
	// lecture : une vue calculée à la volée répondrait différemment selon
	// l'instant de la requête, et rien ne garderait trace du moment où le
	// service a cessé de répondre.
	go reglages.Boucle(reglages.CleBalayageServices, func() {
		if err := hosthandler.MarkStaleServicesOffline(db.GetDatabase()); err != nil {
			logs.Write_Log("ERROR", "cluster: balayage des services échoué : "+err.Error())
		}
		// Purge des services définitivement partis. Passe dans le même
		// cycle que le balayage, mais son délai se compte en heures : les
		// deux répondent à deux questions différentes, « répond-il en ce
		// moment ? » et « existe-t-il encore ? ».
		if err := hosthandler.PurgeDepartedServices(db.GetDatabase()); err != nil {
			logs.Write_Log("ERROR", "cluster: purge des services échouée : "+err.Error())
		}
	})

	// La permission d'amorçage reçoit toutes les actions connues du code, pas
	// une liste recopiée dans du SQL. Passe à chaque démarrage, en INSERT
	// IGNORE : les bases existantes récupèrent ainsi les clés apparues depuis
	// leur création, sans script de migration.
	if err := dbschema.EnsureSuperadminActions(db.GetDatabase(), permission.AllActionKeys()); err != nil {
		logs.Write_Log("ERROR", "bootstrap: actions du groupe superadmin non accordées : "+err.Error())
	}

	cluster.StartManager(db.GetDatabase())
	go duckynetwork.StartDuckyServer()

	if storage.Administrateur_Enable {
		dbschema.CreateDefaultAdminUser(db.GetDatabase())
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
