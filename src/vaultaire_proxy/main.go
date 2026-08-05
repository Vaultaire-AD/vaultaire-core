// vaultaire_proxy — Layer 7 Load Balancer pour LDAP et Ducky-Network.
// S'enregistre comme Host via --add-host et communique avec les Cores via ducky-network.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	duckynetwork "vaultaire_duckynetwork"
	"vaultaire_proxy/balancer"
	"vaultaire_proxy/config"
)

var (
	configPath = flag.String("config", "/opt/vaultaire_proxy/config.yaml", "Chemin du fichier de configuration")
	addHost    = flag.Bool("add-host", false, "Enregistrer ce proxy comme Host auprès du Core (cluster_nodes + groupe)")
	core       = flag.String("core", "", "Override core address (host:port) pour une connexion ponctuelle")
)

func main() {
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	coreAddr := cfg.CoreAddress
	if *core != "" {
		coreAddr = *core
	}
	if coreAddr == "" {
		log.Fatal("config: core_address requis (ou --core)")
	}

	// Connexion ducky au Core : handshake 01_01/01_02 puis 04_01 (register) si --add-host
	client, err := duckynetwork.NewClient(duckynetwork.ClientOpts{
		CoreAddress:     coreAddr,
		ComputeurID:     cfg.Identity.ComputeurID,
		PrivateKeyPEM:   cfg.Identity.PrivateKeyPEM,
		ServerPubKeyPEM: cfg.Identity.ServerPubKey,
	})
	if err != nil {
		log.Fatalf("ducky client: %v", err)
	}

	if err := client.Connect(); err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer client.Close()

	if *addHost {
		hostname := cfg.Proxy.Hostname
		if hostname == "" {
			hostname, _ = os.Hostname()
		}
		if hostname == "" {
			hostname = "vaultaire-proxy"
		}
		fqdn := cfg.Proxy.FQDN
		if fqdn == "" {
			fqdn = hostname
		}
		domain := cfg.Proxy.Domain
		if domain == "" {
			domain = "proxy.vaultaire.fr"
		}
		role := cfg.Proxy.Role
		ip := client.LocalIP()
		if err := client.RegisterHost(hostname, fqdn, ip, role, domain); err != nil {
			log.Fatalf("register_host: %v", err)
		}
		fmt.Println("Host enregistré sur le Core (cluster_nodes).")
	}

	// Service discovery : récupérer la liste des Cores et maintenir le balancer
	cores, err := client.ListCores()
	if err != nil {
		log.Printf("list_cores: %v", err)
	}
	lb := balancer.New(cores)
	go runDiscovery(client, lb)

	// TODO: démarrer les listeners LDAP et Ducky qui forwardent vers lb.Select()
	// Pour l'instant on garde la connexion ouverte et le discovery actif
	fmt.Println("Proxy prêt. Discovery actif. (Listeners LDAP/Ducky à brancher.)")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	fmt.Println("Arrêt.")
}

func runDiscovery(client *duckynetwork.Client, lb *balancer.Balancer) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		cores, err := client.ListCores()
		if err != nil {
			log.Printf("discovery list_cores: %v", err)
		} else {
			lb.UpdateCores(cores)
		}
		// Heartbeat pour rester online dans cluster_nodes
		if client.Hostname() != "" {
			if err := client.SendHeartbeat(client.Hostname()); err != nil {
				log.Printf("heartbeat: %v", err)
			}
		}
	}
}
