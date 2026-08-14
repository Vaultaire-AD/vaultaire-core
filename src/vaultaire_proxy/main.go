// vaultaire_proxy — client service du réseau Ducky.
//
// # Ce que fait cette version
//
//	enrôlement au premier démarrage   (01_05 → 01_08)
//	authentification du serveur       (01_01 → 01_02)
//	authentification du client        (02_01 → 02_11)
//	enregistrement dans le cluster    (04_01 → 04_02)
//	battement de cœur                 (04_07 → 04_08)
//	liste des cores vers qui relayer  (04_03 → 04_04)
//
// PAS ENCORE DE RELAIS. Le proxy est visible du cluster et connaît ses cores ;
// il ne transporte aucun octet. C'est un lot à part, délibérément — le relais
// porte les mots de passe du parc, et il vaut mieux vérifier ce qui le précède
// avant de l'écrire.
//
// # Ce qui bloquait
//
// Les quatre trames 04 étaient écrites CÔTÉ SERVEUR depuis longtemps. Le
// catalogue de types ne les accordait à personne, et rien ne les émettait : un
// proxy déployé n'apparaissait dans aucune liste, aucun agent n'y passait, et
// la table proxy_metrics n'avait jamais reçu une ligne.
//
// # Pourquoi le proxy n'implémente aucune trame
//
// Tout vient de duckynetworkclient/V1, partagé avec les autres clients service.
// Ce fichier lit une configuration et décrit ce que le proxy EST.
//
// C'est la propriété qui compte : le jour où le protocole est durci — comme il
// l'a été en passant de PKCS#1 v1.5 à OAEP —, le proxy en bénéficie sans qu'une
// ligne n'y soit écrite.
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"duckynetworkclient/V1/ducky"
	"duckynetworkclient/V1/duckynetwork/storage"
	"vaultaire_proxy/version"
)

func main() {
	configPath := flag.String("config", "/etc/vaultaire_proxy/config.yaml",
		"chemin du fichier de configuration YAML")
	keyPath := flag.String("keys", "/etc/vaultaire_proxy/.ssh",
		"répertoire des clés et de l'identité")
	noEnroll := flag.Bool("no-enroll", false,
		"refuser l'enrôlement automatique : le proxy s'arrête s'il n'a pas d'identité")
	debug := flag.Bool("debug", false, "journaliser les messages de niveau DEBUG")
	// SANS DÉFAUT devinable : le port est annoncé à tout le parc, et une valeur
	// inventée ferait que les agents s'y connectent sans que rien n'écoute — un
	// délai d'attente par machine, pour un choix que personne n'a fait.
	listen := flag.Int("listen-port", 0,
		"port d'écoute Ducky de ce proxy, annoncé aux agents (obligatoire)")
	domaine := flag.String("domain", "", "domaine de rattachement du nœud")
	flag.Parse()

	if *listen < 1 || *listen > 65535 {
		log.Fatalf("proxy : -listen-port est obligatoire et doit être valide (reçu %d).\n"+
			"  C'est le port annoncé aux agents dans la liste des nœuds joignables.\n"+
			"  Sans lui, ce proxy ne serait annoncé à personne — ou pire, annoncé\n"+
			"  sur un port où rien n'écoute.", *listen)
	}

	// La VERSION de ce binaire, posée AVANT ducky.Start : elle part dans
	// l'inventaire 02_12 et dans l'enregistrement 04_01, tous deux émis pendant
	// le démarrage de la session.
	storage.VersionComposant = version.Info().Complete()

	// Le NOM DE JOURNAL de ce binaire, posé au même endroit et pour une raison
	// voisine : le socle est partagé avec l'agent, et son défaut est
	// « vaultaire_client.log ». Sans cette ligne, le proxy écrirait son journal
	// dans le fichier de l'agent — sous un nom qui annonce autre chose que son
	// contenu, et sans qu'une rotation puisse lui appliquer sa propre politique.
	storage.NomJournal = "vaultaire_proxy.log"

	session, err := ducky.Start(ducky.Options{
		ConfigPath: *configPath,
		KeyPath:    *keyPath,
		Enroll:     !*noEnroll,
		Persistent: true,
		Debug:      *debug,
	})
	if err != nil {
		log.Fatalf("proxy : %v", err)
	}
	log.Printf("proxy en ligne, session %s", session.SessionID)

	// Le raccordement au cluster vient APRÈS Start : l'enregistrement voyage sur
	// une session authentifiée, et l'émettre avant reviendrait à l'envoyer dans
	// le vide.
	//
	// Un échec ici n'arrête PAS le proxy. Il reste connecté et authentifié ; ce
	// qu'il perd est sa visibilité dans le cluster. Traiter cela comme fatal
	// ferait qu'un défaut de déclaration — nom d'hôte introuvable, aucune
	// adresse non locale — coupe un service qui fonctionne par ailleurs.
	if err := ducky.RejoindreCluster(ducky.OptionsCluster{
		Role:      "proxy",
		Domaine:   *domaine,
		Port:      *listen,
		Decouvrir: true, // un proxy doit savoir vers quels cores relayer
	}); err != nil {
		log.Printf("proxy : raccordement au cluster impossible : %v", err)
		log.Printf("proxy : le service reste connecté, mais n'apparaîtra pas " +
			"dans la liste des nœuds joignables")
	}

	// L'arrêt passe par un signal plutôt qu'un os.Exit immédiat : la boucle de
	// réception tourne dans sa goroutine, et lui laisser le temps de fermer
	// proprement évite de laisser une session ouverte côté core jusqu'à
	// expiration.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	log.Println("arrêt demandé")
}
