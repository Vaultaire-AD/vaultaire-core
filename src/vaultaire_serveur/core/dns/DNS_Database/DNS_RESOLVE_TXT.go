package dnsdatabase

import (
	"database/sql"
	"fmt"
	"vaultaire/core/logs"
)

func ResolveTXTRecords(db *sql.DB, zone string) ([]string, error) {
	// Le nom vient d'une requête DNS reçue du réseau : il est validé ici,
	// avant d'approcher la base (TO-DO 105).
	table, err := tableDeZone(zone)
	if err != nil {
		return nil, err
	}

	query := fmt.Sprintf(`SELECT data FROM %s WHERE type = 'TXT'`, table)

	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("erreur récupération TXT pour %s : %v", zone, err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", fmt.Sprintf("Erreur lors de la fermeture de la connexion : %v", err))
		}
	}()

	var results []string
	for rows.Next() {
		var txt string
		if err := rows.Scan(&txt); err != nil {
			return nil, fmt.Errorf("erreur lecture TXT : %v", err)
		}
		results = append(results, txt)
	}
	return results, nil
}
