package dnsdatabase

import (
	dnsstorage "DUCKY/serveur/dns/DNS_Storage"
	"DUCKY/serveur/logs"
	"database/sql"
	"fmt"
	"strings"
)

func GetZoneRecords(db *sql.DB, zone string) ([]dnsstorage.ZoneRecord, error) {
	safeTableName := "zone_" + strings.ReplaceAll(zone, ".", "_")

	query := fmt.Sprintf(`SELECT id, name, type, ttl, data, priority FROM %s`, safeTableName)

	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("erreur lors de la récupération des enregistrements pour %s : %v", zone, err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", fmt.Sprintf("Erreur lors de la fermeture de la connexion : %v", err))
		}
	}()

	var records []dnsstorage.ZoneRecord

	for rows.Next() {
		var r dnsstorage.ZoneRecord
		err := rows.Scan(&r.ID, &r.Name, &r.Type, &r.TTL, &r.Data, &r.Priority)
		if err != nil {
			return nil, fmt.Errorf("erreur de lecture d'un enregistrement : %v", err)
		}
		records = append(records, r)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("erreur d'itération sur les enregistrements : %v", err)
	}

	return records, nil
}
