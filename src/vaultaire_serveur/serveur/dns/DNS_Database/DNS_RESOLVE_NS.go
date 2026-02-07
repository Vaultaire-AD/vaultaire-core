package dnsdatabase

import (
	dnsstorage "vaultaire/serveur/dns/DNS_Storage"
	"vaultaire/serveur/logs"
	"database/sql"
	"fmt"
	"strings"
)

func ResolveNSRecords(db *sql.DB, zone string) ([]dnsstorage.ZoneRecord, error) {
	safeTableName := "zone_" + strings.ReplaceAll(zone, ".", "_")

	query := fmt.Sprintf(`SELECT id, name, type, ttl, data, priority FROM %s WHERE type = 'NS'`, safeTableName)

	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("❌ Erreur DB lors de la récupération des NS de %s : %v", zone, err)
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
		if err := rows.Scan(&r.ID, &r.Name, &r.Type, &r.TTL, &r.Data, &r.Priority); err != nil {
			return nil, fmt.Errorf("❌ Erreur lecture ligne NS : %v", err)
		}
		records = append(records, r)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("❌ Erreur d’itération finale : %v", err)
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("❌ Aucun enregistrement NS trouvé pour %s", zone)
	}

	return records, nil
}
