// vaultaire_proxy — version 1.
//
// # Ce que fait cette version
//
// Elle établit et maintient la présence du proxy dans le cluster Vaultaire :
// enrôlement au premier démarrage, connexion, enregistrement, battement de cœur,
// sortie propre à l'arrêt, réenrôlement si le core ne le reconnaît plus. Rien
// d'autre — la répartition de charge viendra ensuite, sur une base dont on sait
// qu'elle tient.
//
// # Pourquoi le proxy n'implémente aucune trame
//
// Poignée de main, enrôlement, chiffrement, reconnexion : tout vient du dossier
// duckynetwork/, copié depuis ducky-network-sdk et partagé avec les autres
// clients. Ce fichier lit une configuration et décrit ce que le proxy EST.
//
// C'est la propriété qui compte. Le jour où le protocole est durci — comme il
// l'a été en passant de PKCS#1 v1.5 à OAEP —, une réinstallation du dossier
// suffit. La version précédente portait sa propre copie du protocole : elle
// était restée sur PKCS#1 v1.5 et ne pouvait plus parler au core.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"vaultaire_proxy/config"
	"vaultaire_proxy/duckynetwork/keymanagement"
	"vaultaire_proxy/duckynetwork/logs"
	"vaultaire_proxy/duckynetwork/session"
	cluster "vaultaire_proxy/duckynetwork/trames/t04_cluster"
)

func main() {
	configPath := flag.String("config", "/etc/vaultaire_proxy/config.yaml",
		"chemin du fichier de configuration")
	resetIdentity := flag.Bool("reset-identity", false,
		"efface l'identité et force un réenrôlement au démarrage")
	flag.Parse()

	// Le dossier duckynetwork ne journalise rien de lui-même : il ne sait pas
	// où le programme hôte veut écrire. Sans cette ligne, un échec d'enrôlement
	// serait silencieux.
	logs.SetWriter(func(level, message string) { log.Printf("[%s] %s", level, message) })

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("configuration : %v", err)
	}

	store, err := keymanagement.NewStore(cfg.KeyDir)
	if err != nil {
		log.Fatalf("répertoire de clés %s : %v", cfg.KeyDir, err)
	}
	if *resetIdentity {
		if err := store.Reset(); err != nil {
			log.Fatalf("réinitialisation : %v", err)
		}
		logs.Write("INFO", "identité effacée : le proxy se réenrôlera")
	}
	// Une clé du core fournie par configuration l'emporte sur celle en cache :
	// c'est le seul moyen de faire tourner un core dont les clés ont été
	// régénérées sans passer par un « askkey » en clair.
	if cfg.ServerPubKey != "" {
		if err := store.WriteServeurPublicKey(cfg.ServerPubKey); err != nil {
			log.Fatalf("clé publique du core : %v", err)
		}
	}

	// L'arrêt passe par le contexte et non par os.Exit : c'est ce qui laisse le
	// temps d'envoyer la sortie propre (04_14). Sans elle, un arrêt planifié
	// serait indistinguable d'une panne pendant toute la fenêtre de battement,
	// et le cluster afficherait en ligne un proxy volontairement éteint.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	client, err := session.New(buildConfig(cfg))
	if err != nil {
		log.Fatalf("initialisation : %v", err)
	}
	state := &cluster.State{}
	client.Spliter().Handle("04", state.Handler)

	logs.Write("INFO", "proxy "+cfg.Proxy.Version+" — core "+cfg.CoreAddress)

	err = client.Run(ctx)
	if s := client.Session(); s != nil {
		cluster.Deregister(s)
	}
	if err != nil && ctx.Err() == nil {
		log.Fatalf("proxy interrompu : %v", err)
	}
	logs.Write("INFO", "arrêt propre")
}
