package main

import (
	"duckynetworkclient/V1/duckynetwork/decouverte"
	duckytool "duckynetworkclient/V1/duckynetwork/ducky_tool"
	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/sendmessage"
	"duckynetworkclient/V1/duckynetwork/storage"
	"duckynetworkclient/V1/duckynetwork/storage/stosession"
	tramesmanager "duckynetworkclient/V1/duckynetwork/trames_manager"
	"flag"
	"fmt"
	"log"
	"os"
	"time"
	"vaultaire_client/config"
	"vaultaire_client/debugreport"
	"vaultaire_client/gpo"
	pamcommunication "vaultaire_client/pam_communication"
	"vaultaire_client/revocation"
	serveurcommunication "vaultaire_client/serveur_communication"
	"vaultaire_client/sshauth"
	"vaultaire_client/tools"
	localusermanagement "vaultaire_client/tools/local_user_management"
	"vaultaire_client/version"
	yaml_vaultaire "vaultaire_client/yaml"
)

// StartDailyUserCleanup lance le ménage des comptes du domaine, chaque jour à 6 h.
//
// # Il tournait un jour sur deux
//
// La boucle attendait l'heure dite, faisait son travail, puis dormait vingt-
// quatre heures de plus avant de recalculer la prochaine échéance. Elle se
// réveillait donc à 6 h le lendemain, constatait que 6 h était passé « de
// quelques microsecondes », et repartait pour un jour entier : le ménage
// quotidien avait lieu tous les deux jours.
//
// Une seule attente, celle qui mène à la prochaine échéance, suffit et ne peut
// pas dériver.
func StartDailyUserCleanup() {
	go func() {
		defer logs.Recover("tache de fond")
		for {
			now := time.Now()
			next := time.Date(now.Year(), now.Month(), now.Day(), 6, 0, 0, 0, now.Location())

			// !Before plutôt que After : à 6 h 00 min 00 s pile, l'échéance du
			// jour vient d'être servie — c'est celle de demain qu'on vise.
			if !now.Before(next) {
				next = next.Add(24 * time.Hour)
			}

			logs.Write_log("INFO", fmt.Sprintf("Prochain ménage des comptes à %s", next.Format(time.RFC1123)))
			time.Sleep(time.Until(next))

			logs.Write_log("INFO", "Ménage des comptes du domaine restés sans connexion")
			localusermanagement.DeleteUser_Vaultaire_Past_4Days_withoutconnection()
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

	// La VERSION de ce binaire, posée AVANT toute ouverture de session.
	//
	// Le socle ne peut pas la lire lui-même : l'agent l'importe, l'inverse
	// serait un cycle. C'est donc au programme de la déclarer, comme il déclare
	// déjà son Computeur_ID.
	//
	// Avant la session, parce qu'elle part dans l'inventaire 02_12, émis dès
	// l'authentification. Posée après, le premier inventaire l'annoncerait vide.
	storage.VersionComposant = version.Info().Complete()

	// La boucle de connexion de l'agent, et non celle du socle : elle lit
	// /etc/vaultaire_client/client_conf.json, au format JSON déjà déployé sur
	// le parc, là où le socle attend du YAML.
	//
	// DemarrerTunnelMachine est idempotent : l'authentification PAM qui trouve
	// le tunnel en cours de rétablissement ne lance plus une seconde boucle.
	duckytool.DemarrerSessionMachine = serveurcommunication.DemarrerTunnelMachine

	// Les catégories propres à l'agent. 01 et 02 sont fournies par le socle :
	// 01 est lue de façon synchrone avant que la boucle ne démarre, 02 est
	// branchée par le socle lui-même.
	tramesmanager.RegisterHandler("03", sshauth.HandleTrameSSH)
	// 04 : découverte des nœuds joignables. Branchée ici et non dans le socle —
	// c'est l'agent qui décide de l'émettre, et un service du cluster n'a pas
	// les mêmes besoins.
	tramesmanager.RegisterHandler("04", decouverte.HandleTrame)
	tramesmanager.RegisterHandler("05", gpo.HandleTrameGPO)
	tramesmanager.RegisterHandler("06", revocation.HandleTrameRevocation)
}

// bootstrapDecouverte arme la demande périodique de la liste de nœuds.
//
// Après gpo.Bootstrap et pour la même raison : la boucle attend elle-même une
// session utilisable, donc l'appel n'a pas à être ordonné avec l'ouverture du
// tunnel.
func bootstrapDecouverte() {
	decouverte.Configure(func(trame string) {
		// WaitForVaultaireSession plutôt qu'un simple Get : au moment de l'envoi
		// le tunnel peut être en cours de rétablissement après une coupure, et
		// abandonner ferait perdre un cycle entier.
		session, err := stosession.SessionsUser.WaitForVaultaireSession()
		if err != nil || session == nil || session.DuckySession == nil {
			logs.Write_log("WARNING", "découverte : aucune session vaultaire valide, trame non envoyée")
			return
		}
		sendmessage.SendMessage(trame, session.DuckySession)
	}, storage.Computeur_ID)

	// La liste apprise est PERSISTÉE (TO-DO 61) : dans client_conf.json, section
	// « learned », et dans la configuration en mémoire. Seuls les nœuds de
	// confiance arrivent ici — voir decouverte.SurNouvelleListe.
	decouverte.SurNouvelleListe(func(noeuds []decouverte.Noeud) {
		liste := make([]config.ServerConfig, 0, len(noeuds))
		for _, n := range noeuds {
			liste = append(liste, config.ServerConfig{IP: n.IP, Port: n.Port, Hostname: n.Hostname, Role: n.Role})
		}
		ecrit, err := config.MettreAJourAppris(liste)
		switch {
		case err != nil:
			logs.Write_log("ERROR", "découverte : liste apprise non persistée : "+err.Error())
		case ecrit:
			logs.Write_log("INFO", fmt.Sprintf(
				"découverte : %d nœud(s) persisté(s) dans %s", len(liste), config.Chemin()))
		}
	})

	// La bascule vers le nœud prioritaire, second abonné à la même liste
	// (TO-DO 90). Les abonnés s'ajoutent : celui-ci ne désarme pas la
	// persistance ci-dessus.
	serveurcommunication.ArmerBascule()

	decouverte.Demarrer(func() string {
		session, err := stosession.SessionsUser.WaitForVaultaireSession()
		if err != nil || session == nil || session.DuckySession == nil {
			return ""
		}
		return string(session.DuckySession.SessionKey)
	})
}

// purgerGroupesOrphelins affiche, et n'efface que sur confirmation explicite.
//
// # Pourquoi l'affichage est le comportement par défaut
//
// La commande retire des lignes d'un fichier système. Un opérateur qui se
// trompe de machine doit s'en apercevoir AVANT, pas en lisant le compte rendu.
//
// Le vidage a déjà coupé les droits : l'effacement ne gagne que de la propreté.
// Rien ne presse assez pour justifier d'agir sans montrer.
func purgerGroupesOrphelins(confirmer bool) {
	orphelins, err := localusermanagement.GroupesOrphelins()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Erreur :", err)
		os.Exit(1)
	}

	if len(orphelins) == 0 {
		fmt.Println("Aucun groupe du domaine à effacer.")
		return
	}

	fmt.Printf("%d groupe(s) créé(s) par Vaultaire, sans membre, absent(s) du domaine :\n\n", len(orphelins))
	for _, o := range orphelins {
		fmt.Printf("  %-32s GID %d\n", o.Nom, o.GID)
	}

	if !confirmer {
		fmt.Println("\nAucun effacement. Relancer avec --confirm pour effacer ces lignes.")
		fmt.Println("Les fichiers qui portent encore ces GID deviendront orphelins :")
		fmt.Println("`ls -l` n'affichera plus qu'un nombre à la place du nom du groupe.")
		return
	}

	effaces, err := localusermanagement.PurgerGroupesOrphelins()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Erreur :", err)
		os.Exit(1)
	}
	fmt.Printf("\n%d groupe(s) effacé(s) : %v\n", len(effaces), effaces)
}

func main() {
	brancherSocleDucky()

	// ... chargement config ...
	err := config.LoadConfig("/etc/vaultaire_client/client_conf.json")
	if err != nil {
		log.Fatalf("Erreur lors de la lecture du fichier de configuration : %v", err)

	}
	// L'identité de la machine. Son absence n'arrête pas l'agent — il peut
	// encore servir un « fetch-key » et journaliser — mais elle se DIT : sans
	// elle, aucune session ne s'ouvrira et le journal doit le nommer une fois,
	// au démarrage, plutôt qu'à chaque tentative.
	if !yaml_vaultaire.ReadYAMLFile(storage.SoftwarePathResolu()) {
		logs.Write_log("CRITICAL", "identité de la machine illisible ("+
			storage.SoftwarePathResolu()+") : aucune session ne pourra s'ouvrir")
	}

	fetchKey := flag.String("fetch-key", "", "Récupère les clés publiques pour SSH")
	purgeGroupes := flag.Bool("purge-groups", false,
		"Liste les groupes du domaine vidés et effaçables (n'efface rien sans --confirm)")
	confirmer := flag.Bool("confirm", false, "Exécute réellement l'opération demandée")
	// Rapport de debug périodique (vlt_client-Debug.log). La ligne de commande
	// prime sur client_conf.json ("debug": {"enabled", "interval_seconds"}).
	debugRapport := flag.Bool("debug", false,
		"Écrit un rapport d'état complet dans vlt_client-Debug.log, à intervalle régulier")
	debugIntervalle := flag.Int("debug-interval", 0,
		"Période du rapport de debug, en secondes (défaut : client_conf.json, sinon 60)")
	flag.Parse()

	if *purgeGroupes {
		purgerGroupesOrphelins(*confirmer)
		os.Exit(0)
	}

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
		// Le tunnel machine, sur TOUT nœud et dès le démarrage.
		//
		// Il n'était ouvert d'office que sur un serveur ; sur un poste, il
		// attendait la première authentification PAM. Une machine sur laquelle
		// personne ne se connecte restait donc hors ligne : pas de GPO, pas de
		// révocation, absente de `status -c`. La supervision le relance après
		// toute coupure — voir serveur_communication/superviseur.go.
		serveurcommunication.DemarrerTunnelMachine()

		// Transport des GPO. Le comportement est identique pour un client
		// serveur et un client poste : seule la liste des groupes diffère côté
		// serveur. Le premier cycle attend qu'une session mère soit disponible,
		// donc l'appel n'a pas à être ordonné avec l'ouverture du tunnel.
		gpo.Bootstrap()

		// Synchronisation des groupes du domaine.
		//
		// Après gpo.Bootstrap et pour la même raison : la boucle attend
		// elle-même une session utilisable, donc l'appel n'a pas à être
		// ordonné avec l'ouverture du tunnel.
		//
		// Sans elle, l'agent poserait des appartenances dans des groupes qui
		// n'existent pas sur la machine — le mécanisme du point 14 tourne à vide
		// tant que son référentiel n'est pas là.
		sshauth.BootstrapGroupes()

		// Découverte des nœuds joignables. Sans elle, l'agent ne connaît que
		// les serveurs de son fichier de configuration — et ajouter un core au
		// cluster demanderait de repasser sur chaque machine du parc.
		bootstrapDecouverte()

		// Le service d'allocation d'identifiants AVANT le canal PAM.
		//
		// UnixSocketServer bloque : tout ce qui doit vivre à côté se lance avant.
		//
		// Ce service répond au module NSS pour un utilisateur du domaine encore
		// inconnu. Sans lui, sshd refuse le compte avant même d'exécuter
		// AuthorizedKeysCommand, et aucune première connexion n'est possible —
		// sans la moindre trace, puisque rien de Vaultaire n'est exécuté.
		pamcommunication.StartUIDAllocationServer()

		// Rapport de debug : dans la branche du démon SEULEMENT. En mode
		// --fetch-key, la sortie standard est la réponse lue par sshd.
		reglage := config.GetDebug()
		if *debugRapport || reglage.Enabled {
			secondes := reglage.IntervalSeconds
			if *debugIntervalle > 0 {
				secondes = *debugIntervalle
			}
			debugreport.Demarrer(time.Duration(secondes) * time.Second)
		}

		pamcommunication.UnixSocketServer()
	}

}
