package dbgpo

import (
	"database/sql"
	"fmt"
	"vaultaire/core/database"
)

// GetPolicyNamesForGroup retourne les noms des GPO liées à un groupe.
func GetPolicyNamesForGroup(db *sql.DB, groupName string) ([]string, error) {
	if err := database.SanitizeIdentifier(groupName); err != nil {
		return nil, err
	}
	rows, err := db.Query(
		`SELECT gp.gpo_name FROM gpo gp
		 INNER JOIN gpo_group gg ON gg.d_id_gpo = gp.id_gpo
		 INNER JOIN groups g ON g.id_group = gg.d_id_group
		 WHERE g.group_name = ? ORDER BY gp.gpo_name`,
		groupName,
	)
	if err != nil {
		return nil, fmt.Errorf("erreur de lecture des GPO du groupe %s : %v", groupName, err)
	}
	defer closeRows(rows)

	names := []string{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}
