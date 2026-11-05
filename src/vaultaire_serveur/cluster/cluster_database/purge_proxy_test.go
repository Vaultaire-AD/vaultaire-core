package clusterdatabase

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	clusterstorage "vaultaire/cluster/cluster_storage"
)

// La purge d'un proxy (TO-DO 176).

func TestHoteDeLAdresse(t *testing.T) {
	for entree, attendu := range map[string]string{
		"10.0.0.5:44120": "10.0.0.5",
		"[fe80::1]:6666": "fe80::1",
		"10.0.0.5":       "10.0.0.5",
		"  ":             "",
	} {
		if got := HoteDeLAdresse(entree); got != attendu {
			t.Errorf("HoteDeLAdresse(%q) = %q, attendu %q", entree, got, attendu)
		}
	}
	if got := adressesDistinctes("172.18.0.4", "", "172.18.0.4:1", "192.0.2.7"); !reflect.DeepEqual(got,
		[]string{"172.18.0.4", "192.0.2.7"}) {
		t.Errorf("adressesDistinctes = %v", got)
	}
}

func TestEnBaseUnProxyEnMaintenanceSePurgeEtLesCoresAdditionnent(t *testing.T) {
	db := baseDeTest(t)
	suffixe := fmt.Sprint(time.Now().UnixNano())
	proxy := clusterstorage.Node{Hostname: "proxy-" + suffixe, FQDN: "proxy-" + suffixe,
		IPAddress: "172.18.0.4", Role: "proxy", Status: "online", VersionCode: "t",
		Capabilities: "{}", Port: 6666, Proprietaire: "owner-" + suffixe}
	if err := RegisterNode(db, proxy); err != nil {
		t.Fatal(err)
	}
	nexus := "nexus-" + suffixe
	if _, err := db.Exec(`INSERT INTO cluster_nodes (hostname, fqdn, ip_address, role, status,
		version_code, owner_client_id, last_heartbeat, maintenance)
		VALUES (?, ?, '10.0.0.9', 'vaultaire_nexus', 'online', 't', ?, NOW(), TRUE)`,
		nexus, nexus, "o-"+nexus); err != nil {
		t.Fatal(err)
	}

	// Hors maintenance : refusé, comme un core.
	if err := DemanderPurge(db, proxy.Hostname, "alice", 30); !errors.Is(err, ErrPurgeHorsMaintenance) {
		t.Fatalf("purge d'un proxy hors maintenance : %v", err)
	}
	// Un service ne se purge pas.
	if err := DemanderPurge(db, nexus, "alice", 30); !errors.Is(err, ErrPurgePasUnCore) {
		t.Fatalf("purge d'un service : %v", err)
	}

	// L'adresse vue, notée au battement.
	if err := NoterAdresseVue(db, proxy.Proprietaire, "192.0.2.7:51234"); err != nil {
		t.Fatal(err)
	}
	if err := PoserMaintenance(db, proxy.Hostname, true, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := DemanderPurge(db, proxy.Hostname, "alice", 30); err != nil {
		t.Fatalf("purge d'un proxy en maintenance refusée : %v", err)
	}

	trouver := func() (PurgeDeProxy, bool) {
		t.Helper()
		purges, err := PurgesDeProxiesEnCours(db)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range purges {
			if p.Hostname == proxy.Hostname {
				return p, true
			}
		}
		return PurgeDeProxy{}, false
	}
	p, ok := trouver()
	if !ok {
		t.Fatal("la purge demandée n'est pas lue par les cores")
	}
	if !reflect.DeepEqual(p.Adresses, []string{"172.18.0.4", "192.0.2.7"}) || p.Etalement != 30*time.Second ||
		p.Proprietaire != proxy.Proprietaire {
		t.Fatalf("purge lue : %+v", p)
	}
	// TO-DO 216 : l'accès des agents, que la 04_17 nommera.
	if !reflect.DeepEqual(p.AccesAgents, []string{"172.18.0.4:6666"}) {
		t.Errorf("accès des agents : %q", p.AccesAgents)
	}

	// Deux cores écrivent leur part : les fermetures s'additionnent, et la
	// demande reste lisible pour un troisième.
	if err := TerminerPartDePurge(db, proxy.Hostname, p.Demandee, 3); err != nil {
		t.Fatal(err)
	}
	if err := TerminerPartDePurge(db, proxy.Hostname, p.Demandee, 2); err != nil {
		t.Fatal(err)
	}
	var fermees int
	if err := db.QueryRow(`SELECT purge_fermees FROM cluster_nodes WHERE hostname = ?`, proxy.Hostname).
		Scan(&fermees); err != nil || fermees != 5 {
		t.Fatalf("fermetures cumulées : %d (%v), attendu 5", fermees, err)
	}
	if _, ok := trouver(); !ok {
		t.Error("après la part d'un core, la demande n'est plus lue : les autres ne feraient pas la leur")
	}
	// Une part d'une AUTRE demande ne compte pas.
	if err := TerminerPartDePurge(db, proxy.Hostname, p.Demandee.Add(-time.Hour), 9); err != nil {
		t.Fatal(err)
	}
	_ = db.QueryRow(`SELECT purge_fermees FROM cluster_nodes WHERE hostname = ?`, proxy.Hostname).Scan(&fermees)
	if fermees != 5 {
		t.Errorf("une part d'une ancienne demande a été comptée : %d", fermees)
	}

	// Maintenance levée : plus rien à faire.
	if err := PoserMaintenance(db, proxy.Hostname, false, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, ok := trouver(); ok {
		t.Error("une purge de proxy sorti de maintenance est encore lue")
	}
	// Demande trop ancienne : hors fenêtre.
	_ = PoserMaintenance(db, proxy.Hostname, true, "alice")
	if _, err := db.Exec(`UPDATE cluster_nodes SET purge_demandee_le = DATE_SUB(NOW(), INTERVAL 1 HOUR)
		WHERE hostname = ?`, proxy.Hostname); err != nil {
		t.Fatal(err)
	}
	if _, ok := trouver(); ok {
		t.Error("une purge d'il y a une heure est encore lue")
	}
}

// TO-DO 216 : un core en maintenance purgé nomme son accès exposé.
func TestEnBaseLaPurgeDUnCoreDonneSonAccesExpose(t *testing.T) {
	db := baseDeTest(t)
	suffixe := fmt.Sprint(time.Now().UnixNano())
	core := clusterstorage.Node{Hostname: "core-" + suffixe, FQDN: "core-" + suffixe,
		IPAddress: "172.18.0.2", Role: "core", Status: "online", VersionCode: "t",
		Capabilities: "{}", Port: 6666, Proprietaire: "owner-" + suffixe}
	if err := RegisterNode(db, core); err != nil {
		t.Fatal(err)
	}
	adr, port := "192.168.56.106", 7666
	if err := MettreAJourExposition(db, core.Hostname, ExpositionNoeud{AdressePublique: &adr, PortPublic: &port}); err != nil {
		t.Fatal(err)
	}
	if err := PoserMaintenance(db, core.Hostname, true, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := DemanderPurge(db, core.Hostname, "alice", 10); err != nil {
		t.Fatal(err)
	}
	d, afaire, err := PurgeAFaire(db, core.Proprietaire)
	if err != nil || !afaire {
		t.Fatalf("purge à faire : %v %v", afaire, err)
	}
	if !reflect.DeepEqual(d.AccesAgents, []string{"192.168.56.106:7666", "172.18.0.2:6666"}) {
		t.Errorf("accès des agents : %q", d.AccesAgents)
	}
}
