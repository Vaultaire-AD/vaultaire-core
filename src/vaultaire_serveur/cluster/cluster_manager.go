package cluster

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	clusterdatabase "vaultaire/cluster/cluster_database"
	clusterstorage "vaultaire/cluster/cluster_storage"
	"vaultaire/core/clienttype"
	"vaultaire/core/logs"
	"vaultaire/core/reglages"
	"vaultaire/core/storage"
	"vaultaire/core/version"
	hosthandler "vaultaire/ducky-network/host_handler"
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
		Hostname:  hostname,
		FQDN:      fqdn,
		IPAddress: ip,
		Role:      storage.Host_Type,
		Status:    "online",
		// La version COMPLÈTE — sémantique, commit et date — et non la seule
		// constante. C'est ce qu'un exploitant lit dans `vlt cluster list` pour
		// savoir ce qui tourne, et « 2.1.0 » seul ne distingue pas deux cores
		// construits à deux semaines d'écart.
		VersionCode: version.Complete(),
		// Vide, et volontairement : le core n'embarque pas le SDK. C'est lui
		// qui juge les clients, il ne partage pas leur socle réseau.
		VersionSDK:   "",
		Capabilities: capabilitiesJSON,
		Port:         port,
		Empreinte:    empreinte,

		// Le core est propriétaire de SA ligne, et personne d'autre.
		//
		// Il ne s'enregistre pas par le réseau — il écrit ici, depuis son propre
		// processus, sans session. Le propriétaire porte donc un préfixe réservé
		// que ProprietaireDepuisSession refuse : aucun client, quel que soit son
		// identifiant, ne peut revendiquer cette ligne.
		//
		// Par hostname : sur un cluster à plusieurs cores, une valeur commune
		// laisserait chacun écrire la ligne des autres.
		Proprietaire: clusterdatabase.ProprietaireCoreLocal(hostname),
	}

	if err := clusterdatabase.RegisterNode(db, node); err != nil {
		logs.Write_Log("ERROR", "cluster: failed to register node: "+err.Error())
	} else {
		logs.Write_Log("INFO", "cluster: node registered in database as core (port "+
			strconv.Itoa(port)+")")
	}

	go startHeartbeatLoop(db, node)
	go startCleanupLoop(db)
}

// startHeartbeatLoop met à jour régulièrement le heartbeat du nœud courant.
//
// La cadence est relue à chaque tour : un ticker créé une fois garderait sa
// période même après changement du réglage, et rien ne le dirait — la valeur
// s'afficherait, sans agir.
func startHeartbeatLoop(db *sql.DB, node clusterstorage.Node) {
	// Le core bat sur SA ligne, désignée par le même propriétaire que celui de
	// son enregistrement. Battre par hostname reviendrait à rafraîchir la ligne
	// qui porte ce nom, quelle qu'elle soit.
	proprietaire := node.Proprietaire

	reglages.Boucle(reglages.CleBattementCluster, func() {
		touchees, err := clusterdatabase.UpdateHeartbeat(db, proprietaire)
		if err != nil {
			logs.Write_Log("ERROR", "cluster: failed to update heartbeat: "+err.Error())
			return
		}
		if touchees == 0 {
			// La ligne de ce core a disparu — oubliée après une longue absence
			// (veille de l'hôte, coupure), ou base réinitialisée sous lui.
			//
			// Il se RÉENREGISTRE, au lieu de demander un redémarrage : sans
			// cela, il battait indéfiniment dans le vide et se croyait en ligne
			// alors qu'il n'était plus annoncé à personne — le symptôme du
			// TO-DO 84, « les cores ne réintègrent pas le cluster après une
			// veille ».
			if err := clusterdatabase.RegisterNode(db, node); err != nil {
				logs.Write_Log("ERROR", "cluster: la ligne de ce core a disparu de "+
					"cluster_nodes et son réenregistrement a échoué : "+err.Error())
				return
			}
			logs.Write_Log("WARNING", "cluster: la ligne de ce core avait disparu de "+
				"cluster_nodes — réenregistré. Ses réglages d'exposition, de priorité "+
				"et d'affinité sont à refaire s'il en avait.")
		}
	})
}

// startCleanupLoop applique périodiquement les règles de mise hors ligne / purge.
//
// L'oubli des nœuds suit le délai de purge des services (« cluster
// purge-delay », 24 h par défaut) : un seul délai pour répondre à « ce nœud
// existe-t-il encore ? », quel que soit son genre.
func startCleanupLoop(db *sql.DB) {
	reglages.Boucle(reglages.CleNettoyageCluster, func() {
		n, err := clusterdatabase.CleanupStaleNodes(db, hosthandler.PurgeDelay(db), clienttype.ServiceNames())
		if err != nil {
			logs.Write_Log("ERROR", "cluster: cleanup stale nodes failed: "+err.Error())
			return
		}
		if n > 0 {
			logs.Write_Log("WARNING", fmt.Sprintf(
				"cluster: %d nœud(s) hors ligne depuis plus que le délai de purge oublié(s) — "+
					"leurs réglages d'exposition, de priorité et d'affinité sont perdus", n))
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
