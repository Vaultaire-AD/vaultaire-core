package webserveur

import (
	"strings"
	"testing"
	"time"

	clusterstorage "vaultaire/cluster/cluster_storage"
	act "vaultaire/core/action"
)

// Maintenance, purge, oubli sur la page Cluster (TO-DO 146, 147).

func coreEnService() clusterstorage.Node {
	return clusterstorage.Node{Hostname: "core-1", FQDN: "core-1", Role: "core", Status: "online",
		IPAddress: "10.0.0.10", Port: 6666, ExposeAuxAgents: true, LastHeartbeat: time.Now(),
		Maintenance: &clusterstorage.EtatMaintenance{}}
}

func TestUnNoeudEnServiceProposeLaMaintenanceEtPasLOubli(t *testing.T) {
	n := coreEnService()
	html := rendreLaPageCluster(t, donneesCluster{Username: "alice", Nodes: []clusterstorage.Node{n}, Selection: &n})
	for _, attendu := range []string{`value="set_maintenance"`, `name="mode" value="on"`, "Mettre en maintenance"} {
		if !strings.Contains(html, attendu) {
			t.Errorf("fiche sans %q", attendu)
		}
	}
	for _, interdit := range []string{`value="forget_node"`, `value="purge_node"`, "<span class=\"badge\">maintenance</span>"} {
		if strings.Contains(html, interdit) {
			t.Errorf("un core en service propose %q", interdit)
		}
	}
}

func TestUnCoreEnMaintenanceProposeLaPurgeEtDitOuEnEstLaPurge(t *testing.T) {
	n := coreEnService()
	n.Maintenance = &clusterstorage.EtatMaintenance{Active: true, Par: "root", Depuis: time.Now(),
		PurgeDemandee: time.Now(), PurgePar: "root"}
	html := rendreLaPageCluster(t, donneesCluster{Username: "alice", Nodes: []clusterstorage.Node{n}, Selection: &n})
	for _, attendu := range []string{"<span class=\"badge\">maintenance</span>", "purge en cours",
		`name="mode" value="off"`, `value="purge_node"`, "<strong>en cours</strong>", "portail et de l'API"} {
		if !strings.Contains(html, attendu) {
			t.Errorf("page sans %q", attendu)
		}
	}
}

// Un proxy en maintenance propose la purge des sessions qu'il relaie (TO-DO 176).
func TestUnProxyEnMaintenanceProposeLaPurgeDesSessionsRelayees(t *testing.T) {
	n := coreEnService()
	n.Role, n.Hostname = "proxy", "proxy-1"
	n.Maintenance = &clusterstorage.EtatMaintenance{Active: true, Depuis: time.Now()}
	html := rendreLaPageCluster(t, donneesCluster{Username: "alice", Nodes: []clusterstorage.Node{n}, Selection: &n})
	for _, attendu := range []string{`value="purge_node"`, "Purger les sessions relayées", "NAT"} {
		if !strings.Contains(html, attendu) {
			t.Errorf("page du proxy sans %q", attendu)
		}
	}
}

// Un service en maintenance, lui, n'en propose pas : il ne relaie rien.
func TestUnServiceEnMaintenanceNeProposePasDePurge(t *testing.T) {
	n := coreEnService()
	n.Role, n.Hostname = "vaultaire_nexus", "nexus-1"
	n.Maintenance = &clusterstorage.EtatMaintenance{Active: true, Depuis: time.Now()}
	html := rendreLaPageCluster(t, donneesCluster{Username: "alice", Nodes: []clusterstorage.Node{n}, Selection: &n})
	if strings.Contains(html, `value="purge_node"`) {
		t.Error("un service propose une purge")
	}
}

func TestUnNoeudHorsLigneProposeLOubli(t *testing.T) {
	n := coreEnService()
	n.Status = "offline"
	n.Maintenance = nil // état illisible : la page s'affiche quand même
	html := rendreLaPageCluster(t, donneesCluster{Username: "alice", Nodes: []clusterstorage.Node{n}, Selection: &n})
	if !strings.Contains(html, `value="forget_node"`) || !strings.Contains(html, "Oublier ce nœud") {
		t.Error("un nœud hors ligne ne propose pas l'oubli")
	}
}

// Le dernier core : la demande est rejouée par un bouton, « confirm » compris.
func TestLaConfirmationRejoueLaDemande(t *testing.T) {
	n := coreEnService()
	data := donneesCluster{Username: "alice", Nodes: []clusterstorage.Node{n},
		Confirmation: &confirmationCluster{Motif: "core-1 est le DERNIER core servi aux agents : RIEN n'a été changé.",
			Action: "set_maintenance", Champs: act.Params{"node": "core-1", "mode": "on", "confirm": "yes"}}}
	html := rendreLaPageCluster(t, data)
	for _, attendu := range []string{"DERNIER core", `name="action" value="set_maintenance"`,
		`name="confirm" value="yes"`, `name="mode" value="on"`, "Confirmer malgré tout"} {
		if !strings.Contains(html, attendu) {
			t.Errorf("confirmation sans %q", attendu)
		}
	}
}
