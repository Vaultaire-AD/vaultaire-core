package clusterdatabase

import (
	"database/sql"
	clusterstorage "vaultaire/cluster/cluster_storage"
)

func RegisterNode(db *sql.DB, n clusterstorage.Node) error {
	query := `INSERT INTO cluster_nodes (hostname, fqdn, ip_address, role, status, version_code, capabilities) 
              VALUES (?, ?, ?, ?, 'online', ?, ?) 
              ON DUPLICATE KEY UPDATE ip_address=?, status='online', last_heartbeat=NOW()`
	_, err := db.Exec(query, n.Hostname, n.FQDN, n.IPAddress, n.Role, n.VersionCode, n.Capabilities, n.IPAddress)
	return err
}

func UpdateHeartbeat(db *sql.DB, hostname string) error {
	_, err := db.Exec("UPDATE cluster_nodes SET last_heartbeat=NOW(), status='online' WHERE hostname=?", hostname)
	return err
}

func GetActiveNodesByRole(db *sql.DB, role string) ([]clusterstorage.Node, error) {
	rows, err := db.Query("SELECT id_node, hostname, fqdn FROM cluster_nodes WHERE role=? AND status='online'", role)
	// ... implémentation du mapping des rows vers slice de Node ...
	return nil, err
}
