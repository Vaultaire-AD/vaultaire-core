package dnsdatabase

import (
	dnsstorage "DUCKY/serveur/dns/DNS_Storage"
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
	defer rows.Close()

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
