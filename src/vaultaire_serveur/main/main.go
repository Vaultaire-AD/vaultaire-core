package main

import (
	"time"

	"log"
	"net"
	"os"
	"strconv"
	"strings"

	dbschema "vaultaire/core/database/db_schema"

	"vaultaire/cluster"
	"vaultaire/core/action"
	commandcertificate "vaultaire/core/command/command_certificate"
	configurationfile "vaultaire/core/configuration_file"
	db "vaultaire/core/database"
	dbauthpolicy "vaultaire/core/database/db_authpolicy"
	dbenrollment "vaultaire/core/database/db_enrollment"
	dbgpo "vaultaire/core/database/db_gpo"
	dbgroups "vaultaire/core/database/db_groups"
	dbjournaux "vaultaire/core/database/db_journaux"
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
	keymanagement "vaultaire/ducky-network/key_management"
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

	// Le chemin de la configuration n'est plus écrit en dur.
	//
	// $VAULTAIRE_CONFIG l'emporte, sinon /etc/vaultaire/ puis /opt/vaultaire/ —
	// voir configuration_file.CheminConfig. Un core doit pouvoir tourner
	// ailleurs qu'à un emplacement unique : sous un autre utilisateur, depuis un
	// dépôt cloné, dans un conteneur qui range sa configuration autrement.
	cheminConfig, consultes := configurationfile.CheminConfig()
	if err := configurationfile.LoadConfig(cheminConfig); err != nil {
		// Le message dit OÙ l'on a cherché et QUOI faire. L'erreur brute de
		// os.Open — « no such file or directory » — est vraie et inutile : elle
		// ne dit ni ce que le fichier doit contenir, ni où en trouver un modèle.
		log.Fatalf("%v", configurationfile.ErreurConfigIntrouvable(consultes, err))
	}
	logs.Write_Log("INFO", "config: chargée depuis "+cheminConfig)

	// LES VALEURS DE DÉMONSTRATION ARRÊTENT LE DÉMARRAGE — TO-DO 99.
	//
	// ICI, et pas plus loin : avant l'ouverture de la base, avant la création du
	// schéma, avant qu'aucun service n'écoute. Un serveur qui refuse de démarrer
	// sur sa configuration ne doit pas avoir eu le temps de créer quoi que ce
	// soit — sans quoi la correction se ferait sur une base déjà peuplée d'un
	// compte qu'on voulait justement empêcher de naître.
	//
	// Un AVERTISSEMENT n'aurait servi à rien : il est lu une fois, le jour de
	// l'installation, par quelqu'un qui regarde si le service monte. Le refus
	// arrive au seul moment où quelqu'un est devant l'écran et peut corriger.
	if err := configurationfile.VerifierValeursLivrees(); err != nil {
		log.Fatalf("configuration refusée : %v", err)
	}

	db.InitDatabase()
	dbschema.Create_DataBase(db.GetDatabase())

	// Journal commun des cores, AUSSITÔT la base ouverte (TO-DO 91).
	//
	// Le plus tôt possible : chaque ligne émise avant ce branchement manque au
	// journal commun — elle reste sur la sortie standard. Seules la lecture de
	// la configuration et l'ouverture de la base sont dans ce cas.
	//
	// Un échec ici n'arrête PAS le core, contrairement aux autres schémas : le
	// journal commun est un confort de lecture, pas une condition de service.
	// Le core journalise alors comme avant, sur sa sortie standard, et le
	// portail se replie sur sa mémoire en le disant.
	journalCommun := dbjournaux.CreateTables(db.GetDatabase()) == nil
	if journalCommun {
		dbjournaux.Demarrer(db.GetDatabase)
	} else {
		logs.Write_Log("ERROR", "journaux: journal commun désactivé sur ce core — "+
			"les lignes restent sur la sortie standard")
	}

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

	// Purge du journal commun : au démarrage PUIS à la cadence du réglage.
	// Boucle attend un tour avant de travailler, et un core qu'on redémarre
	// chaque nuit ne purgerait sinon jamais.
	//
	// APRÈS le schéma d'authentification, qui crée `server_settings` : lancée
	// plus tôt, la purge lisait sa rétention dans une table absente — valeur
	// par défaut, et deux avertissements à chaque démarrage sur base neuve.
	if journalCommun {
		purgerJournaux := func() {
			if _, err := dbjournaux.Purger(db.GetDatabase(),
				reglages.Duree(reglages.CleRetentionJournaux)); err != nil {
				logs.Write_LogCode("ERROR", logs.CodeLogPurge, "journaux: "+err.Error())
			}
		}
		go purgerJournaux()
		go reglages.Boucle(reglages.ClePurgeJournaux, purgerJournaux)
	}

	// L'historique des applications GPO suit la MÊME cadence de purge que les
	// journaux, et non la sienne.
	//
	// Une troisième boucle pour une table qui ne reçoit une ligne qu'aux
	// changements aurait fait un réglage de plus à comprendre, pour un travail
	// qui tient en une requête. Les deux rétentions restent distinctes — c'est
	// la question à laquelle chacune répond qui diffère, pas le rythme du
	// ménage.
	purgerHistoriqueGPO := func() {
		n, err := dbgpo.PurgerHistoriqueApplication(db.GetDatabase(),
			reglages.Duree(reglages.CleRetentionHistoGPO))
		if err != nil {
			logs.Write_Log("ERROR", "gpo: purge de l'historique : "+err.Error())
			return
		}
		if n > 0 {
			logs.Write_Log("INFO",
				"gpo: "+strconv.FormatInt(n, 10)+" transition(s) d'application purgée(s)")
		}
	}
	go purgerHistoriqueGPO()
	go reglages.Boucle(reglages.ClePurgeJournaux, purgerHistoriqueGPO)

	// Clés d'enrôlement des clients service.
	//
	// Avant tout service acceptant des connexions : un service qui tenterait de
	// s'enrôler avant que la table existe recevrait un refus serveur, alors que
	// sa clé est valide.
	if err := dbenrollment.CreateTables(db.GetDatabase()); err != nil {
		log.Fatalf("Erreur lors de la création du schéma d'enrôlement : %v", err)
	}

	// La cadence de rafraîchissement des GPO, telle que le core la décide.
	//
	// db_gpo s'en sert pour dire si une machine est « en retard » : trois cycles
	// de silence. La valeur était une constante recopiée de l'agent — allonger
	// la cadence de l'un sans toucher à l'autre faisait apparaître tout le parc
	// en retard du jour au lendemain. Il n'y a plus qu'une source, et c'est
	// celle-ci : le même réglage part aux agents dans les trames 05_02 et 05_03.
	//
	// Une fonction et non une valeur : « settings set gpo_refresh_minutes »
	// prend effet sans redémarrage.
	dbgpo.CadenceAgent = func() time.Duration {
		return reglages.Duree(reglages.CleRafraichissementGPO)
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
		// Rétention des métriques, dans le même cycle et pour la même
		// raison d'économie : une troisième boucle pour une requête qui ne
		// fait rien la plupart du temps coûterait plus en lisibilité qu'en
		// ressources.
		//
		// La suppression est BORNÉE par passage — voir LotPurgeMetriques.
		// Le premier passage après la mise en service est celui qui a le
		// plus à supprimer, c'est-à-dire que le comportement le plus lourd
		// arriverait au moment le moins attendu.
		if _, err := hosthandler.PurgeMetriquesAnciennes(db.GetDatabase()); err != nil {
			logs.Write_Log("ERROR", "cluster: purge des métriques échouée : "+err.Error())
		}
	})

	// La permission d'amorçage reçoit toutes les actions connues du code, pas
	// une liste recopiée dans du SQL. Passe à chaque démarrage, en INSERT
	// IGNORE : les bases existantes récupèrent ainsi les clés apparues depuis
	// leur création, sans script de migration.
	if err := dbschema.EnsureSuperadminActions(db.GetDatabase(), permission.AllActionKeys()); err != nil {
		logs.Write_Log("ERROR", "bootstrap: actions du groupe superadmin non accordées : "+err.Error())
	}

	// Le verbe « remove » (Détacher) sépare le retrait d'un groupe de la
	// suppression. Les délégués qui détachaient avec « delete » gardent ce
	// pouvoir : la migration recopie leurs droits, une seule fois.
	if err := dbschema.MigrerCleDetacher(db.GetDatabase()); err != nil {
		logs.Write_Log("ERROR", "bootstrap: "+err.Error())
	}

	// Domaines parents manquants : les bases créées avant que la création d'un
	// groupe ne crée ses parents peuvent porter `infra.acme.lan` sans
	// `acme.lan`. Sans effet quand l'arborescence est complète.
	if crees, err := dbgroups.CreerDomainesParentsManquants(db.GetDatabase()); err != nil {
		logs.Write_Log("ERROR", "bootstrap: domaines parents : "+err.Error())
	} else if len(crees) > 0 {
		logs.Write_Log("INFO", "bootstrap: domaine(s) parent(s) créé(s) : "+strings.Join(crees, ", "))
	}

	// Les CLÉS du core, avant tout ce qui les lit.
	//
	// Elles étaient générées par StartDuckyServer, lancé en goroutine juste
	// après cette ligne : sur une base neuve, StartManager lisait donc une clé
	// qui n'existait pas encore, et le serveur mourait sur une panique — au
	// premier démarrage, celui où l'on comprend le moins ce qui se passe.
	//
	// Synchroniquement et ICI : un prérequis amorcé dans le démarrage d'un
	// service crée un ordre implicite entre des composants qui ne se
	// connaissent pas, et cet ordre se casse au premier réagencement.
	if err := keymanagement.EnsureServerKeys(); err != nil {
		log.Fatalf("Impossible d'amorcer les clés du core : %v\n"+
			"  Le serveur ne peut ni authentifier un client ni s'annoncer au cluster.\n"+
			"  Vérifiez l'accès à la base et la table `certificates`.", err)
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
