package clusterdatabase

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"

	clusterstorage "vaultaire/cluster/cluster_storage"
	dbschema "vaultaire/core/database/db_schema"
)

// Les réglages d'un nœud survivent à son absence (TO-DO 85).
//
// # Le défaut
//
// CleanupStaleNodes supprimait toute ligne muette depuis cinq minutes. Un
// proxy redémarré lentement, un hôte en veille : la ligne disparaissait, le
// nœud revenait par un INSERT neuf, et l'adresse publique, le port exposé, la
// priorité, le retrait de rotation et l'affinité étaient perdus. La recette
// du 24/09 l'a vu comme « il faut ressaisir l'IP publique et le port ».

func TestLOubliNeVisePasLesServices(t *testing.T) {
	q, args := requeteOubli(24*time.Hour, []string{"vaultaire_nexus", "vaultaire_web"})
	for _, attendu := range []string{"status = 'offline'", "role NOT IN (?,?)", "last_heartbeat <"} {
		if !strings.Contains(q, attendu) {
			t.Errorf("requête sans « %s » :\n%s", attendu, q)
		}
	}
	if len(args) != 3 || args[0] != int64(86400) || args[1] != "vaultaire_nexus" {
		t.Fatalf("arguments = %v", args)
	}
}

func TestSansDelaiRienNEstOublie(t *testing.T) {
	// Zéro vaut « jamais », comme pour la purge des services. La fonction doit
	// rendre avant toute suppression — une base nulle suffit à le prouver :
	// la mise hors ligne échoue, pas l'oubli.
	if _, err := CleanupStaleNodes(nil, 0, nil); err == nil {
		t.Fatal("base nulle acceptée")
	}
}

// --- contre une vraie base (VAULTAIRE_TEST_DSN) --------------------------------

func baseDeTest(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("VAULTAIRE_TEST_DSN")
	if dsn == "" {
		t.Skip("VAULTAIRE_TEST_DSN absent : pas de base de test MariaDB")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	dbschema.Create_DataBase(db)
	return db
}

func TestEnBaseLesReglagesSurviventAUneAbsence(t *testing.T) {
	db := baseDeTest(t)
	suffixe := fmt.Sprint(time.Now().UnixNano())
	proxy := clusterstorage.Node{Hostname: "proxy-" + suffixe, FQDN: "proxy-" + suffixe,
		IPAddress: "10.0.0.2", Role: "proxy", Status: "online", VersionCode: "t",
		Capabilities: "{}", Port: 6666, Proprietaire: "owner-" + suffixe}
	if err := RegisterNode(db, proxy); err != nil {
		t.Fatal(err)
	}
	adr, port, prio, expose := "203.0.113.5", 16666, 3, false
	if err := MettreAJourExposition(db, proxy.Hostname, ExpositionNoeud{
		AdressePublique: &adr, PortPublic: &port, Priorite: &prio, ExposeAuxAgents: &expose}); err != nil {
		t.Fatal(err)
	}

	// Dix minutes sans battement : une veille, un redémarrage lent.
	if _, err := db.Exec(`UPDATE cluster_nodes SET last_heartbeat = DATE_SUB(NOW(), INTERVAL 10 MINUTE)
		WHERE hostname = ?`, proxy.Hostname); err != nil {
		t.Fatal(err)
	}
	if _, err := CleanupStaleNodes(db, 24*time.Hour, []string{"vaultaire_nexus"}); err != nil {
		t.Fatal(err)
	}

	// Le nœud revient.
	if err := RegisterNode(db, proxy); err != nil {
		t.Fatal(err)
	}
	var gotAdr string
	var gotPort, gotPrio int
	var gotExpose bool
	if err := db.QueryRow(`SELECT adresse_publique, port_public, priorite, expose_aux_agents
		FROM cluster_nodes WHERE hostname = ?`, proxy.Hostname).Scan(&gotAdr, &gotPort, &gotPrio, &gotExpose); err != nil {
		t.Fatalf("ligne du nœud introuvable après dix minutes d'absence : %v", err)
	}
	if gotAdr != adr || gotPort != port || gotPrio != prio || gotExpose != expose {
		t.Fatalf("réglages après retour : %s:%d prio %d exposé %v — attendu %s:%d prio %d exposé %v",
			gotAdr, gotPort, gotPrio, gotExpose, adr, port, prio, expose)
	}
}

func TestEnBaseLOubliAttendLeDelaiEtEpargneLesServices(t *testing.T) {
	db := baseDeTest(t)
	suffixe := fmt.Sprint(time.Now().UnixNano())
	inserer := func(nom, role string, absence string) {
		t.Helper()
		if _, err := db.Exec(`INSERT INTO cluster_nodes (hostname, fqdn, ip_address, role, status,
			version_code, owner_client_id, last_heartbeat)
			VALUES (?, ?, '10.0.0.9', ?, 'offline', 't', ?, DATE_SUB(NOW(), INTERVAL `+absence+`))`,
			nom, nom, role, "o-"+nom); err != nil {
			t.Fatal(err)
		}
	}
	inserer("parti-"+suffixe, "proxy", "3 DAY")
	inserer("absent-"+suffixe, "proxy", "2 HOUR")
	inserer("nexus-"+suffixe, "vaultaire_nexus", "3 DAY")

	if _, err := CleanupStaleNodes(db, 24*time.Hour, []string{"vaultaire_nexus"}); err != nil {
		t.Fatal(err)
	}
	existe := func(nom string) bool {
		var n int
		_ = db.QueryRow(`SELECT COUNT(*) FROM cluster_nodes WHERE hostname = ?`, nom).Scan(&n)
		return n == 1
	}
	if existe("parti-" + suffixe) {
		t.Error("un proxy parti depuis trois jours n'est pas oublié")
	}
	if !existe("absent-" + suffixe) {
		t.Error("un proxy absent deux heures a été supprimé : ses réglages seraient perdus")
	}
	if !existe("nexus-" + suffixe) {
		t.Error("un service supprimé ici : sa purge est celle de PurgeDepartedServices, qui retire aussi son client")
	}
}
