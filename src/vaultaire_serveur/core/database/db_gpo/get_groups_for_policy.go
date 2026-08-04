package dbgpo

import (
	"database/sql"
	"fmt"
)

// GetGroupsForPolicy retourne les noms des groupes liés à une GPO.
func GetGroupsForPolicy(db *sql.DB, policyID int) ([]string, error) {
	rows, err := db.Query(
		`SELECT g.group_name FROM groups g
		 INNER JOIN gpo_group gg ON gg.d_id_group = g.id_group
		 WHERE gg.d_id_gpo = ? ORDER BY g.group_name`,
		policyID,
	)
	if err != nil {
		return nil, fmt.Errorf("erreur de lecture des groupes de la GPO %d : %v", policyID, err)
	}
	defer closeRows(rows)

	groups := []string{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		groups = append(groups, name)
	}
	return groups, rows.Err()
}
