package webserveur

import (
	"strings"
	"testing"
	"time"

	clusterstorage "vaultaire/cluster/cluster_storage"
)

// La page Cluster montre les sessions de chaque core (TO-DO 148), et ne montre
// JAMAIS zéro pour un core qui ne publie rien.

func clusterAvecDeuxCores() (donneesCluster, *clusterstorage.Node) {
	mesure := time.Now()
	mesure1 := clusterstorage.MetriquesSessions{Machines: 42, Tunnels: 45, Comptes: 3, Poignees: 2, Mesure: mesure}
	c1 := clusterstorage.Node{Hostname: "core-1", FQDN: "core-1", Role: "core", Status: "online",
		IPAddress: "10.0.0.10", Port: 6666, ExposeAuxAgents: true, LastHeartbeat: mesure, Sessions: &mesure1}
	c2 := clusterstorage.Node{Hostname: "core-2", FQDN: "core-2", Role: "core", Status: "online",
		IPAddress: "10.0.0.11", Port: 6666, ExposeAuxAgents: true, LastHeartbeat: mesure}
	return donneesCluster{Username: "alice", Section: "cluster",
		Nodes: []clusterstorage.Node{c1, c2}}, &c2
}

func TestLaListeMontreLesSessionsDesCores(t *testing.T) {
	data, _ := clusterAvecDeuxCores()
	html := rendreLaPageCluster(t, data)
	if !strings.Contains(html, "<th>Sessions</th>") || !strings.Contains(html, "42 m · 3 c · 2 p") {
		t.Fatal("la colonne des sessions est absente, ou ne porte pas la mesure du core")
	}
	if strings.Contains(html, "0 m · 0 c") {
		t.Error("un core sans mesure est affiché à zéro — on le croirait vide")
	}
}

func TestLaFicheDUnCoreDetailleSesSessions(t *testing.T) {
	data, _ := clusterAvecDeuxCores()
	data.Selection = &data.Nodes[0]
	html := rendreLaPageCluster(t, data)
	for _, attendu := range []string{"<h3>Sessions</h3>", "<td>42</td><td>45</td><td>3</td><td>2</td>", "déclarative"} {
		if !strings.Contains(html, attendu) {
			t.Errorf("fiche sans %q", attendu)
		}
	}
}

func TestLaFicheDUnCoreMuetLeDit(t *testing.T) {
	data, muet := clusterAvecDeuxCores()
	data.Selection = muet
	html := rendreLaPageCluster(t, data)
	if !strings.Contains(html, "Aucune mesure récente") {
		t.Error("la fiche d'un core qui ne publie rien ne le dit pas")
	}
}

func TestLaFicheDUnProxyNAPasDeSessions(t *testing.T) {
	data := proxyOuvert()
	if strings.Contains(rendreLaPageCluster(t, data), "<h3>Sessions</h3>") {
		t.Error("la fiche d'un proxy affiche une section de sessions de core")
	}
}
