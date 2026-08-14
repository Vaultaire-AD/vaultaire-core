package cluster

import (
	"database/sql"
	"encoding/json"
	"net"
	"os"
	"strconv"
	"strings"

	clusterdatabase "vaultaire/cluster/cluster_database"
	clusterstorage "vaultaire/cluster/cluster_storage"
	"vaultaire/core/logs"
	"vaultaire/core/reglages"
	"vaultaire/core/storage"
	"vaultaire/core/version"
	keymanagement "vaultaire/ducky-network/key_management"
)

// StartManager initialise l'enregistrement du nœud courant et les tâches périodiques
// (heartbeat + nettoyage des nœuds inactifs).
func StartManager(db *sql.DB) {
	if db == nil {
		logs.Write_Log("ERROR", "cluster: StartManager called with nil database")
		return
	}

	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "unknown-core"
	}

	ip := detectPrimaryIP()
	fqdn := hostname
	if ip != "" {
		fqdn = hostname
	}

	capabilitiesJSON := buildCapabilitiesJSON()

	// Le PORT d'écoute Ducky, déclaré par le core sur lui-même.
	//
	// Sans lui, ce core ne figure dans aucune liste servie aux agents : la
	// requête les écarte, faute de savoir où les joindre. Sur une installation
	// mono-core, cela reviendrait à ne rien annoncer du tout — et personne ne
	// verrait le rapport entre « les agents ne trouvent plus de serveur » et une
	// colonne ajoutée au schéma.
	//
	// La valeur vient de la même configuration que l'écoute elle-même, jamais
	// d'une constante : les deux doivent bouger ensemble, et le seul moyen d'en
	// être sûr est qu'elles aient une source unique.
	port, err := strconv.Atoi(strings.TrimSpace(storage.ServeurLisetenPort))
	if err != nil || port < 1 || port > 65535 {
		logs.Write_Log("ERROR", "cluster: port d'écoute illisible ("+
			storage.ServeurLisetenPort+") — ce core ne sera pas annoncé aux agents")
		port = 0
	}

	// L'EMPREINTE de la clé publique de ce core, déclarée sur lui-même.
	//
	// C'est ce que la liste distribuée transporte, et ce qui permet à un agent
	// d'apprendre un core sans devoir accepter sa clé en aveugle. Elle est
	// calculée depuis le certificat ServerMainKeyName en base — la MÊME source
	// que celle servie à `askkey`. En prendre une autre rendrait possible
	// qu'elles divergent, et l'agent refuserait alors une clé légitime.
	//
	// Les clés sont amorcées par main (keymanagement.EnsureServerKeys), avant
	// cet appel. C'est ce qui manquait : sur une base neuve, cette ligne lisait
	// une clé qui n'existait pas encore.
	//
	// Vide en cas d'échec plutôt qu'une valeur de repli : la requête écarte les
	// nœuds sans empreinte, donc ce core n'est pas annoncé. Ne pas être annoncé
	// est un défaut de disponibilité ; être annoncé avec une empreinte fausse
	// est un défaut d'authentification, et le second se répare beaucoup moins
	// bien que le premier.
	empreinte, err := keymanagement.EmpreinteDuCore()
	if err != nil {
		logs.Write_Log("ERROR", "cluster: empreinte du core indisponible ("+err.Error()+
			") — ce core ne sera pas annoncé aux agents")
		empreinte = ""
	}

	node := clusterstorage.Node{
		Hostname:     hostname,
		FQDN:         fqdn,
		IPAddress:    ip,
		Role:         storage.Host_Type,
		Status:       "online",
		// La version COMPLÈTE — sémantique, commit et date — et non la seule
		// constante. C'est ce qu'un exploitant lit dans `vlt cluster list` pour
		// savoir ce qui tourne, et « 2.1.0 » seul ne distingue pas deux cores
		// construits à deux semaines d'écart.
		VersionCode:  version.Complete(),
		// Vide, et volontairement : le core n'embarque pas le SDK. C'est lui
		// qui juge les clients, il ne partage pas leur socle réseau.
		VersionSDK:   "",
		Capabilities: capabilitiesJSON,
		Port:         port,
		Empreinte:    empreinte,
	}

	if err := clusterdatabase.RegisterNode(db, node); err != nil {
		logs.Write_Log("ERROR", "cluster: failed to register node: "+err.Error())
	} else {
		logs.Write_Log("INFO", "cluster: node registered in database as core (port "+
			strconv.Itoa(port)+")")
	}

	go startHeartbeatLoop(db, hostname)
	go startCleanupLoop(db)
}

// startHeartbeatLoop met à jour régulièrement le heartbeat du nœud courant.
//
// La cadence est relue à chaque tour : un ticker créé une fois garderait sa
// période même après changement du réglage, et rien ne le dirait — la valeur
// s'afficherait, sans agir.
func startHeartbeatLoop(db *sql.DB, hostname string) {
	reglages.Boucle(reglages.CleBattementCluster, func() {
		if err := clusterdatabase.UpdateHeartbeat(db, hostname); err != nil {
			logs.Write_Log("ERROR", "cluster: failed to update heartbeat: "+err.Error())
		}
	})
}

// startCleanupLoop applique périodiquement les règles de mise hors ligne / purge.
func startCleanupLoop(db *sql.DB) {
	reglages.Boucle(reglages.CleNettoyageCluster, func() {
		if err := clusterdatabase.CleanupStaleNodes(db); err != nil {
			logs.Write_Log("ERROR", "cluster: cleanup stale nodes failed: "+err.Error())
		}
	})
}

// detectPrimaryIP essaie de trouver une adresse IP non loopback.
func detectPrimaryIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if (iface.Flags & net.FlagUp) == 0 {
			continue
		}
		if (iface.Flags & net.FlagLoopback) != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue
			}
			return ip.String()
		}
	}
	return ""
}

// buildCapabilitiesJSON expose les services activés sur ce core.
func buildCapabilitiesJSON() string {
	type caps struct {
		LDAP  bool `json:"ldap"`
		LDAPS bool `json:"ldaps"`
		Web   bool `json:"web"`
		DNS   bool `json:"dns"`
		API   bool `json:"api"`
	}
	c := caps{
		LDAP:  storage.Ldap_Enable,
		LDAPS: storage.Ldaps_Enable,
		Web:   storage.Website_Enable,
		DNS:   storage.Dns_Enable,
		API:   storage.API_Enable,
	}
	b, err := json.Marshal(c)
	if err != nil {
		return "{}"
	}
	return string(b)
}
