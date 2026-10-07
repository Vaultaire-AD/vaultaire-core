// vaultaire_proxy — client service du réseau Ducky.
//
// # Ce que fait cette version
//
//	relais ouverts, depuis la copie locale ou le fichier — AVANT toute session
//	enrôlement au premier démarrage   (01_05 → 01_08)
//	authentification du serveur       (01_01 → 01_02)
//	authentification du client        (02_01 → 02_11)
//	enregistrement dans le cluster    (04_01 → 04_02)
//	battement de cœur                 (04_07 → 04_08)
//	liste des cores vers qui relayer  (04_03 → 04_04)
//
//	relais Ducky des agents → cores   (TO-DO 38, lot 4 — relais.go)
//
// # Le relais
//
// Depuis la 2.2, le proxy transporte les connexions Ducky des agents vers les
// cores, SANS LES LIRE : il ne termine ni la session ni le chiffrement, et
// l'agent vérifie la clé du core au bout du tunnel. Les relais HTTPS (vers
// Nexus, par exemple) et LDAP/S sont prévus dans la configuration, pas encore
// activables. Voir docs/proxy/.
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
	"time"

	"duckynetworkclient/V1/ducky"
	"duckynetworkclient/V1/duckynetwork/decouverte"
	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/storage"
	"vaultaire_proxy/relais"
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

	// Le seuil de rotation de CE binaire.
	//
	// Le socle en pose un de poste — 20 Mo. Un proxy voit passer le trafic de
	// plusieurs machines : à ce seuil, il tournerait plusieurs fois par jour en
	// fonctionnement sain, et ses 30 archives ne couvriraient plus un mois mais
	// quelques jours. La protection contre l'emballement mangerait la rétention.
	//
	// Une ligne ici, et non un réglage : c'est une propriété de ce programme,
	// pas une décision d'exploitation à reprendre sur chaque machine.
	logs.TailleMaxJournal = 100 << 20

	// Les relais sont LUS avant tout le reste : une faute dans leur déclaration
	// arrête le proxy ici, avant qu'il n'ouvre une connexion ou ne s'annonce.
	liste, err := relais.Charger(*configPath, *listen)
	if err != nil {
		log.Fatalf("proxy : %v", err)
	}

	// La session Ducky est LANCÉE, pas attendue (TO-DO 158). Ce qui reste fatal
	// ici est ce sans quoi le proxy ne peut rien faire : une configuration
	// illisible, ou pas d'identité et pas de core pour s'enrôler.
	if err := ducky.Lancer(ducky.Options{
		ConfigPath: *configPath,
		KeyPath:    *keyPath,
		Enroll:     !*noEnroll,
		Persistent: true,
		Debug:      *debug,
	}); err != nil {
		log.Fatalf("proxy : %v", err)
	}

	// LES RELAIS (TO-DO 38, lot 4) — ouverts AVANT d'avoir une session.
	//
	// Ils s'ouvraient après le raccordement au cluster, donc jamais sans core :
	// un proxy redémarré pendant une coupure du lien s'arrêtait au bout de
	// trente secondes sans avoir ouvert un port, y compris ceux de ses relais
	// vers des cibles locales, qui n'ont pas besoin du core.
	//
	// Le pilote part de la copie locale de la dernière liste reçue du core
	// (TO-DO 141), sinon du fichier. Le relais Ducky se rabat sur les serveurs
	// du fichier tant que la découverte n'a rien appris ; sans core joignable il
	// refuse franchement, et l'agent passe au nœud suivant.
	//
	// Un relais du FICHIER qui ne peut pas écouter reste FATAL : ce proxy est
	// annoncé aux agents sur ce port, et y laisser un port mort en ferait un
	// trou noir.
	pilote := nouveauPilote(*configPath, *listen)
	if err := pilote.demarrer(liste); err != nil {
		log.Fatalf("proxy : %v", err)
	}
	lancerLeBilan()
	// Branché avant le raccordement : une liste de relais poussée par le core
	// dès l'enregistrement ne doit pas arriver sans personne pour la lire.
	decouverte.SurConfigurationRelais(pilote.surConfiguration)

	// Le raccordement, lui, attend la session — en fond, et sans limite : voir
	// raccordement.go.
	logs.Go("raccordement au core", raccordement{
		attendre: func(delai time.Duration) (string, error) {
			session, err := ducky.Attendre(delai)
			if err != nil {
				return "", err
			}
			return session.SessionID, nil
		},
		rejoindre: func() error {
			return ducky.RejoindreCluster(ducky.OptionsCluster{
				Role:      "proxy",
				Domaine:   *domaine,
				Port:      *listen,
				Decouvrir: true, // un proxy doit savoir vers quels cores relayer
				Services:  relais.ServicesSuivis(liste),
				// Les compteurs des relais, à la cadence du battement (TO-DO 108).
				// Une fonction, et non des valeurs : les relais changent pendant
				// que le proxy tourne (TO-DO 141).
				Metriques: metriquesRelais,
			})
		},
		ensuite:      func() { logs.Go("compte rendu des relais", pilote.boucleDeCompteRendu) },
		relaisActifs: pilote.relaisActifs,
		journal:      func(niveau, message string) { logs.Write_log(niveau, message) },
		premiere:     PremiereAlarme,
		rappel:       RappelSansCore,
		maintenant:   time.Now,
	}.executer)

	// L'arrêt passe par un signal plutôt qu'un os.Exit immédiat : la boucle de
	// réception tourne dans sa goroutine, et lui laisser le temps de fermer
	// proprement évite de laisser une session ouverte côté core jusqu'à
	// expiration.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	log.Println("arrêt demandé")
	pilote.fermer()
}
