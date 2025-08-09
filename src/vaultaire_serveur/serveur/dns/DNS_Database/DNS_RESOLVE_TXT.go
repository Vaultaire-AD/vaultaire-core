package dnsdatabase

import (
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
	defer rows.Close()

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
