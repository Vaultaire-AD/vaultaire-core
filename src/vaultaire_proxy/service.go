package main

import (
	"context"

	"vaultaire_proxy/config"
	"vaultaire_proxy/duckynetwork/session"
	"vaultaire_proxy/duckynetwork/storage"
	cluster "vaultaire_proxy/duckynetwork/trames/t04_cluster"
)

// buildConfig traduit la configuration du proxy en configuration de session.
func buildConfig(cfg config.Config) session.Config {
	return session.Config{
		ServerAddress: cfg.CoreAddress,
		KeyDir:        cfg.KeyDir,
		EnrollmentKey: cfg.Enrollment.Key,
		Label:         cfg.Enrollment.Label,

		// # Pourquoi le réenrôlement est un choix de configuration
		//
		// À vrai, un proxy dont le core a été réinstallé reprend sa place tout
		// seul : c'est ce qu'on veut d'un service qui doit tenir sans personne.
		//
		// Mais c'est aussi ce qui lui ferait reprendre sa place après une
		// RÉVOCATION délibérée, tant que la clé d'enrôlement reste valide.
		// L'administrateur qui coupe l'accès doit alors penser à révoquer aussi
		// la clé. Laissé à faux, le proxy s'arrête et l'incident se voit.
		AllowReEnroll: cfg.AllowReEnroll,

		OnReady: onReady(cfg),
	}
}

// onReady réenregistre le proxy dans le cluster à chaque connexion.
//
// À chaque connexion, et non une seule fois : l'enregistrement vit dans la table
// du cluster du core, et une purge, une réinstallation ou un simple redémarrage
// du core peuvent l'avoir effacé pendant que le proxy, lui, tournait toujours.
func onReady(cfg config.Config) func(*storage.DuckySession) error {
	return func(s *storage.DuckySession) error {
		reg := cluster.Registration{
			Version:      cfg.Proxy.Version,
			Endpoint:     cfg.Proxy.Endpoint,
			Capabilities: cfg.Proxy.Capabilities,
		}
		if err := cluster.Register(s, reg); err != nil {
			return err
		}

		// Le battement s'arrête de lui-même dès que l'envoi échoue, c'est-à-dire
		// dès que la connexion tombe. La goroutine ne survit donc pas à la
		// session qui l'a lancée.
		go cluster.RunHeartbeat(context.Background(), s, cluster.DefaultHeartbeatPeriod)
		return nil
	}
}
