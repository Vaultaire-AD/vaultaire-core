package dnsdatabase

import (
	"database/sql"
	"fmt"
)

// GetZoneTable retourne le nom de la table SQL correspondant à une zone DNS
func GetZoneTable(db *sql.DB, zone string) (string, error) {
	var tableName string

	query := `SELECT table_name FROM dns_zones WHERE zone_name = ? LIMIT 1`
	err := db.QueryRow(query, zone).Scan(&tableName)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("zone '%s' non trouvée dans dns_zones", zone)
		}
		return "", fmt.Errorf("erreur lors de la requête : %v", err)
	}

	return tableName, nil
}
