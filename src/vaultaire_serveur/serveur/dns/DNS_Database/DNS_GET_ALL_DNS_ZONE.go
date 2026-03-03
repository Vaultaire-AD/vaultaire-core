package dnsdatabase

import (
	dnsstorage "vaultaire/serveur/dns/DNS_Storage"
	"vaultaire/serveur/logs"
	"database/sql"
	"fmt"
)

// GetAllDNSZones récupère toutes les zones DNS depuis la table dns_zones
func GetAllDNSZones(db *sql.DB) ([]dnsstorage.Zone, error) {
	rows, err := db.Query(`SELECT zone_name, table_name FROM dns_zones`)
	if err != nil {
		return nil, fmt.Errorf("erreur lors de la récupération des zones DNS : %v", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", fmt.Sprintf("Erreur lors de la fermeture de la connexion : %v", err))
		}
	}()

	var zones []dnsstorage.Zone

	for rows.Next() {
		var z dnsstorage.Zone
		if err := rows.Scan(&z.ZoneName, &z.TableName); err != nil {
			return nil, fmt.Errorf("erreur de lecture ligne zone DNS : %v", err)
		}
		zones = append(zones, z)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("erreur d'itération sur les zones DNS : %v", err)
	}

	return zones, nil
}
