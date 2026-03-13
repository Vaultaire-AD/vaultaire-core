package cluster

import (
	"database/sql"
	"encoding/json"
	"net"
	"os"
	"time"

	clusterdatabase "vaultaire/cluster/cluster_database"
	clusterstorage "vaultaire/cluster/cluster_storage"
	"vaultaire/serveur/logs"
	"vaultaire/serveur/storage"
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

	node := clusterstorage.Node{
		Hostname:     hostname,
		FQDN:         fqdn,
		IPAddress:    ip,
		Role:         "core",
		Status:       "online",
		VersionCode:  "dev-core",
		Capabilities: capabilitiesJSON,
	}

	if err := clusterdatabase.RegisterNode(db, node); err != nil {
		logs.Write_Log("ERROR", "cluster: failed to register node: "+err.Error())
	} else {
		logs.Write_Log("INFO", "cluster: node registered in database as core")
	}

	go startHeartbeatLoop(db, hostname)
	go startCleanupLoop(db)
}

// startHeartbeatLoop met à jour régulièrement le heartbeat du nœud courant.
func startHeartbeatLoop(db *sql.DB, hostname string) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if err := clusterdatabase.UpdateHeartbeat(db, hostname); err != nil {
			logs.Write_Log("ERROR", "cluster: failed to update heartbeat: "+err.Error())
		}
	}
}

// startCleanupLoop applique périodiquement les règles de mise hors ligne / purge.
func startCleanupLoop(db *sql.DB) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if err := clusterdatabase.CleanupStaleNodes(db); err != nil {
			logs.Write_Log("ERROR", "cluster: cleanup stale nodes failed: "+err.Error())
		}
	}
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

