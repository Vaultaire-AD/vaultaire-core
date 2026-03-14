package clusterdatabase

import (
	"database/sql"
	"time"

	clusterstorage "vaultaire/cluster/cluster_storage"
)

func RegisterNode(db *sql.DB, n clusterstorage.Node) error {
	// 1) Essayer de mettre à jour par IP (cas container qui reboot avec hostname différent)
	if n.IPAddress != "" {
		res, err := db.Exec(
			`UPDATE cluster_nodes 
             SET hostname=?, fqdn=?, role=?, status='online', version_code=?, capabilities=?, last_heartbeat=NOW()
             WHERE ip_address=?`,
			n.Hostname, n.FQDN, n.Role, n.VersionCode, n.Capabilities, n.IPAddress,
		)
		if err == nil {
			if rows, _ := res.RowsAffected(); rows > 0 {
				return nil
			}
		}
	}

	// 2) Sinon, insertion classique basée sur l'unicité hostname/fqdn
	query := `INSERT INTO cluster_nodes (hostname, fqdn, ip_address, role, status, version_code, capabilities) 
              VALUES (?, ?, ?, ?, 'online', ?, ?) 
              ON DUPLICATE KEY UPDATE ip_address=VALUES(ip_address), role=VALUES(role), version_code=VALUES(version_code), capabilities=VALUES(capabilities), status='online', last_heartbeat=NOW()`
	_, err := db.Exec(query, n.Hostname, n.FQDN, n.IPAddress, n.Role, n.VersionCode, n.Capabilities)
	return err
}

func UpdateHeartbeat(db *sql.DB, hostname string) error {
	_, err := db.Exec("UPDATE cluster_nodes SET last_heartbeat=NOW(), status='online' WHERE hostname=?", hostname)
	return err
}

func GetActiveNodesByRole(db *sql.DB, role string) ([]clusterstorage.Node, error) {
	rows, err := db.Query(`SELECT id_node, hostname, fqdn, ip_address, role, status, version_code, capabilities, last_heartbeat 
                            FROM cluster_nodes 
                            WHERE role=? AND status='online'`, role)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var nodes []clusterstorage.Node
	for rows.Next() {
		var n clusterstorage.Node
		var lastHeartbeat time.Time
		if err := rows.Scan(&n.ID, &n.Hostname, &n.FQDN, &n.IPAddress, &n.Role, &n.Status, &n.VersionCode, &n.Capabilities, &lastHeartbeat); err != nil {
			return nil, err
		}
		n.LastHeartbeat = lastHeartbeat
		nodes = append(nodes, n)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return nodes, nil
}

// GetAllNodes retourne tous les nœuds, quelque soit leur état.
func GetAllNodes(db *sql.DB) ([]clusterstorage.Node, error) {
	rows, err := db.Query(`SELECT id_node, hostname, fqdn, ip_address, role, status, version_code, capabilities, last_heartbeat 
                            FROM cluster_nodes 
                            ORDER BY role, hostname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var nodes []clusterstorage.Node
	for rows.Next() {
		var n clusterstorage.Node
		var lastHeartbeat time.Time
		if err := rows.Scan(&n.ID, &n.Hostname, &n.FQDN, &n.IPAddress, &n.Role, &n.Status, &n.VersionCode, &n.Capabilities, &lastHeartbeat); err != nil {
			return nil, err
		}
		n.LastHeartbeat = lastHeartbeat
		nodes = append(nodes, n)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return nodes, nil
}

// CleanupStaleNodes applique la politique :
// - >1 minute sans heartbeat => status='offline'
// - >5 minutes sans heartbeat => suppression.
func CleanupStaleNodes(db *sql.DB) error {
	// Mettre hors ligne les nœuds inactifs depuis plus d'une minute
	if _, err := db.Exec(`UPDATE cluster_nodes 
                           SET status='offline' 
                           WHERE status='online' AND last_heartbeat < DATE_SUB(NOW(), INTERVAL 1 MINUTE)`); err != nil {
		return err
	}
	// Supprimer les nœuds inactifs depuis plus de cinq minutes
	if _, err := db.Exec(`DELETE FROM cluster_nodes 
                           WHERE last_heartbeat < DATE_SUB(NOW(), INTERVAL 5 MINUTE)`); err != nil {
		return err
	}
	return nil
}

