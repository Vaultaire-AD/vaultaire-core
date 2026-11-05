package hosthandler

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"

	clusterdatabase "vaultaire/cluster/cluster_database"
	dbschema "vaultaire/core/database/db_schema"
	"vaultaire/core/storage"
)

// TO-DO 231 : un service qui bat reste en ligne, quelle que soit la zone de la
// base. Le battement était écrit en UTC par Go et comparé à NOW() par le
// balayage des nœuds : sur une base en +01:00, le Nexus paraissait vieux d'une
// heure et repassait hors ligne à chaque tour.
func TestEnBaseUnServiceQuiBatResteEnLigneHorsUTC(t *testing.T) {
	dsn := os.Getenv("VAULTAIRE_TEST_DSN")
	if dsn == "" {
		t.Skip("VAULTAIRE_TEST_DSN absent : pas de base de test MariaDB")
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	db, err := sql.Open("mysql", dsn+sep+"time_zone=%27%2B01%3A00%27")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	dbschema.Create_DataBase(db)

	id := fmt.Sprint("svc-horloge-", time.Now().UnixNano())
	if _, err := db.Exec(`INSERT INTO cluster_nodes (hostname, fqdn, ip_address, role, status, version_code, owner_client_id, last_heartbeat)
		VALUES (?, ?, 'https://n:8843', 'vaultaire_nexus', 'offline', 't', ?, NOW() - INTERVAL 1 DAY)`, id, id, id); err != nil {
		t.Fatal(err)
	}
	defer db.Exec(`DELETE FROM cluster_nodes WHERE hostname = ?`, id)

	session := &storage.DuckySession{BoundClientSoftwareID: id, BoundClientType: "vaultaire_nexus"}
	if _, err := handleServiceHeartbeat(db, storage.Trames_struct_client{}, session); err != nil {
		t.Fatal(err)
	}
	if _, err := clusterdatabase.CleanupStaleNodes(db, 0, nil); err != nil {
		t.Fatal(err)
	}
	if err := MarkStaleServicesOffline(db); err != nil {
		t.Fatal(err)
	}
	var statut string
	if err := db.QueryRow(`SELECT status FROM cluster_nodes WHERE hostname = ?`, id).Scan(&statut); err != nil {
		t.Fatal(err)
	}
	if statut != "online" {
		t.Fatalf("service qui vient de battre : %s — le battement et le balayage n'ont pas la même horloge", statut)
	}
}
