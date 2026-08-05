// vaultaire_proxy — version 1.
//
// # Ce que fait cette version
//
// Elle établit et maintient la présence du proxy dans le cluster Vaultaire :
// enrôlement au premier démarrage, connexion, enregistrement, battement de cœur,
// sortie propre à l'arrêt. Rien d'autre — la répartition de charge viendra
// ensuite, sur une base dont on sait qu'elle tient.
//
// # Pourquoi tout le protocole vient du SDK
//
// Le proxy n'implémente aucune trame lui-même. La poignée de main,
// l'enrôlement, le chiffrement, la reconnexion et l'auto-réinitialisation vivent
// dans ducky-network-sdk, commun à tous les clients. Ce fichier ne fait que lire
// une configuration et décrire ce que le proxy est.
//
// C'est la propriété qui compte : le jour où le protocole est durci — comme il
// l'a été en passant de PKCS#1 v1.5 à OAEP —, le proxy en bénéficie sans qu'une
// ligne n'y soit écrite. La version précédente, qui portait sa propre copie du
// protocole, était restée sur PKCS#1 v1.5 et ne pouvait plus parler au core.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	duckynetwork "vaultaire_duckynetwork"

	"vaultaire_proxy/config"
)

func main() {
	configPath := flag.String("config", "/etc/vaultaire_proxy/config.yaml", "chemin du fichier de configuration")
	resetIdentity := flag.Bool("reset-identity", false,
		"efface l'identité et force un réenrôlement au démarrage")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("configuration : %v", err)
	}

	if *resetIdentity {
		if err := duckynetwork.ResetIdentity(cfg.IdentityPath); err != nil {
			log.Fatalf("réinitialisation : %v", err)
		}
		logLine("INFO", "identité effacée : le proxy se réenrôlera")
	}

	// L'arrêt passe par le contexte plutôt que par un os.Exit : c'est ce qui
	// laisse au SDK le temps d'envoyer sa sortie propre (04_14). Sans elle, un
	// arrêt planifié serait indistinguable d'une panne pendant toute la fenêtre
	// de battement de cœur, et le core afficherait le proxy en ligne alors qu'il
	// vient d'être arrêté volontairement.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	service := duckynetwork.ServiceConfig{
		CoreAddress:        cfg.CoreAddress,
		ServerPublicKeyPEM: cfg.ServerPubKey,
		EnrollmentKey:      cfg.Enrollment.Key,
		IdentityPath:       cfg.IdentityPath,
		Label:              cfg.Enrollment.Label,
		Info: duckynetwork.ServiceInfo{
			Version:      cfg.Proxy.Version,
			Endpoint:     cfg.Proxy.Endpoint,
			Capabilities: cfg.Proxy.Capabilities,
		},
		Logf: logLine,
	}

	logLine("INFO", fmt.Sprintf("proxy %s — core %s", cfg.Proxy.Version, cfg.CoreAddress))

	if err := duckynetwork.RunService(ctx, service); err != nil {
		log.Fatalf("proxy interrompu : %v", err)
	}
	logLine("INFO", "arrêt propre")
}

// logLine écrit un événement sur la sortie standard.
//
// Le SDK ne journalise rien lui-même : il ne sait pas où le programme hôte veut
// écrire. C'est le proxy qui décide, et pour l'instant c'est la sortie standard,
// que systemd ou Docker collectent.
func logLine(level, message string) {
	log.Printf("[%s] %s", level, message)
}
