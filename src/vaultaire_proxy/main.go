// vaultaire_proxy — client service du réseau Ducky.
//
// # Ce que fait cette version
//
// Elle existe sur le réseau, et rien de plus :
//
//	enrôlement au premier démarrage   (01_05 → 01_08)
//	authentification du serveur       (01_01 → 01_02)
//	authentification du client        (02_01 → 02_11)
//
// Pas de cluster, pas de répartition de charge. Ce socle est ce sur quoi le
// reste se posera, et il vaut mieux le savoir juste avant d'empiler.
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
)

func main() {
	configPath := flag.String("config", "/etc/vaultaire_proxy/config.yaml",
		"chemin du fichier de configuration YAML")
	keyPath := flag.String("keys", "/etc/vaultaire_proxy/.ssh",
		"répertoire des clés et de l'identité")
	noEnroll := flag.Bool("no-enroll", false,
		"refuser l'enrôlement automatique : le proxy s'arrête s'il n'a pas d'identité")
	debug := flag.Bool("debug", false, "journaliser les messages de niveau DEBUG")
	flag.Parse()

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

	// L'arrêt passe par un signal plutôt qu'un os.Exit immédiat : la boucle de
	// réception tourne dans sa goroutine, et lui laisser le temps de fermer
	// proprement évite de laisser une session ouverte côté core jusqu'à
	// expiration.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	log.Println("arrêt demandé")
}
