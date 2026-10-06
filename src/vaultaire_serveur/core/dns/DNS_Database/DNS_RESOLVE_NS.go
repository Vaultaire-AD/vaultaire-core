package dnsdatabase

import (
	"database/sql"
	"fmt"
	dnsstorage "vaultaire/core/dns/DNS_Storage"
	"vaultaire/core/logs"
)

func ResolveNSRecords(db *sql.DB, zone string) ([]dnsstorage.ZoneRecord, error) {
	// Le nom vient d'une requête DNS reçue du réseau : il est validé ici,
	// avant d'approcher la base (TO-DO 105).
	table, err := tableDeZone(zone)
	if err != nil {
		return nil, err
	}

	query := fmt.Sprintf(`SELECT id, name, type, ttl, data, priority FROM %s WHERE type = 'NS'`, table)

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
