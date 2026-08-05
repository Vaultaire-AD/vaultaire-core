// Package cluster traite la catégorie 04 : appartenance au cluster.
//
// Un client SERVICE (proxy, interface web, extension) s'y déclare, y bat, et en
// sort. Un agent n'émet pas de 04 : il déclare sa machine en 02_12.
package cluster

import (
	"fmt"
	"strings"

	"duckynetwork/duckynetwork/logs"
	"duckynetwork/duckynetwork/sendmessage"
	"duckynetwork/duckynetwork/storage"
)

// Codes de la catégorie.
const (
	RegisterService   = "04_09"
	RegisterOK        = "04_10"
	ServiceError      = "04_11"
	Heartbeat         = "04_12"
	HeartbeatOK       = "04_13"
	DeregisterService = "04_14"
)

// Registration décrit ce qu'un service déclare de lui-même.
//
// Ni son type ni son identifiant n'y figurent : le core les tient de la session,
// où ils ont été fixés à partir d'une identité prouvée. Les redemander ici
// laisserait un service déclarer ce qu'il veut être.
type Registration struct {
	// Version du logiciel, telle qu'affichée dans le cluster.
	Version string
	// Endpoint est l'adresse à laquelle ce service est joignable.
	Endpoint string
	// Capabilities est de l'INVENTAIRE, pas un droit : ce que le service peut
	// émettre reste décidé par son type au catalogue du core.
	Capabilities []string
}

// Register envoie 04_09.
//
// # À rejouer après chaque reconnexion
//
// L'enregistrement vit dans la table du cluster, pas dans la session ; mais le
// core répond « service non enregistré » si la ligne a disparu — réinstallation,
// purge d'un service parti trop longtemps. Rejouer 04_09 à chaque connexion
// coûte une trame et évite de battre dans le vide.
func Register(session *storage.DuckySession, reg Registration) error {
	if strings.TrimSpace(reg.Version) == "" || strings.TrimSpace(reg.Endpoint) == "" {
		return fmt.Errorf("version et endpoint sont requis pour s'enregistrer")
	}
	message := sendmessage.BuildClientTrame(
		RegisterService, "serveur_central", session.SessionID, session.Username, session.ComputeurID,
		reg.Version, reg.Endpoint, strings.Join(reg.Capabilities, ","))
	if err := sendmessage.SendMessage(message, session, ""); err != nil {
		return fmt.Errorf("envoi de 04_09 : %w", err)
	}
	logs.Write("INFO", "enregistrement dans le cluster demandé")
	return nil
}
