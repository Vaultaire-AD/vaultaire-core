package display

import (
	"strings"
	"testing"
	"time"

	clusterstorage "vaultaire/cluster/cluster_storage"
)

// La fiche d'un nœud et la colonne SESSIONS (TO-DO 148).
//
// Ce qu'elles gardent : un core qui ne publie rien n'est JAMAIS affiché à zéro
// — c'est la lecture qui ferait purger un nœud qu'on croit vide (TO-DO 147).

func coreDeTest() clusterstorage.Node {
	return clusterstorage.Node{Hostname: "core-1", Role: "core", Status: "online",
		IPAddress: "10.0.0.10", Port: 6666, ExposeAuxAgents: true,
		LastHeartbeat: time.Date(2026, 10, 11, 13, 0, 0, 0, time.UTC)}
}

func TestLaFicheDUnCoreDetailleSesSessions(t *testing.T) {
	n := coreDeTest()
	mesure := time.Date(2026, 10, 11, 13, 0, 0, 0, time.UTC)
	n.Sessions = &clusterstorage.MetriquesSessions{Machines: 42, Tunnels: 45, Comptes: 3, Poignees: 1, Mesure: mesure}

	f := DisplayClusterNode(n, mesure.Add(40*time.Second))
	for _, attendu := range []string{"42 (tunnels ouverts : 45)", "3 session(s)", "Poignées de main", "il y a 40 s"} {
		if !strings.Contains(f, attendu) {
			t.Errorf("la fiche ne dit pas %q :\n%s", attendu, f)
		}
	}
}

func TestUnCoreSansMesureNEstPasVide(t *testing.T) {
	f := DisplayClusterNode(coreDeTest(), time.Now())
	if !strings.Contains(f, "aucune récente") {
		t.Errorf("core sans mesure :\n%s", f)
	}
	if strings.Contains(f, "Machines") {
		t.Errorf("un core sans mesure affiche des compteurs :\n%s", f)
	}
}

func TestUnProxyNePublieRienEtLeDit(t *testing.T) {
	p := coreDeTest()
	p.Role, p.Hostname = "vaultaire_proxy", "proxy-1"
	if f := DisplayClusterNode(p, time.Now()); !strings.Contains(f, "seul un core publie") {
		t.Errorf("proxy :\n%s", f)
	}
}

func TestLaListePorteLaColonneSessions(t *testing.T) {
	c := coreDeTest()
	c.Sessions = &clusterstorage.MetriquesSessions{Machines: 42, Comptes: 3, Poignees: 2}
	muet := coreDeTest()
	muet.Hostname = "core-2"
	sortie := DisplayClusterNodes("", []clusterstorage.Node{c, muet})
	if !strings.Contains(sortie, "SESSIONS") || !strings.Contains(sortie, "42 m · 3 c · 2 p") {
		t.Fatalf("colonne absente :\n%s", sortie)
	}
	if strings.Contains(sortie, "0 m · 0 c") {
		t.Errorf("le core muet est affiché à zéro :\n%s", sortie)
	}
}

// La maintenance dans la liste et dans la fiche (TO-DO 147).
func TestLaMaintenanceSeVoit(t *testing.T) {
	c := coreDeTest()
	debut := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	c.Maintenance = &clusterstorage.EtatMaintenance{Active: true, Par: "root", Depuis: debut,
		PurgeDemandee: debut.Add(time.Minute), PurgePar: "root"}
	if e := etatLisible(c); e != "online · maint. (purge)" {
		t.Errorf("état = %q", e)
	}
	f := DisplayClusterNode(c, debut.Add(2*time.Minute))
	if !strings.Contains(f, "en maintenance depuis") || !strings.Contains(f, "en cours") {
		t.Errorf("fiche :\n%s", f)
	}

	c.Maintenance.PurgeTerminee = debut.Add(3 * time.Minute)
	c.Maintenance.Fermees = 7
	if f := DisplayClusterNode(c, debut.Add(4*time.Minute)); !strings.Contains(f, "7 session(s) fermée(s)") {
		t.Errorf("purge terminée :\n%s", f)
	}
	if etatLisible(coreDeTest()) != "online" {
		t.Error("un core sans état de maintenance n'affiche pas son état brut")
	}
}
