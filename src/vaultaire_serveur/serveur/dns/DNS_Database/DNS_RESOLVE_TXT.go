package dnsdatabase

import (
	"vaultaire/serveur/logs"
	"database/sql"
	"fmt"
	"strings"
)

func ResolveTXTRecords(db *sql.DB, zone string) ([]string, error) {
	safeTableName := "zone_" + strings.ReplaceAll(zone, ".", "_")

	query := fmt.Sprintf(`SELECT data FROM %s WHERE type = 'TXT'`, safeTableName)

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
