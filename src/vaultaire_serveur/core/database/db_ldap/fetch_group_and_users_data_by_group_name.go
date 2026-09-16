package dbldap

import (
	"database/sql"
	"fmt"
)

// fetchGroupAndUsersDataByGroupName exécute la requête SQL pour récupérer les informations
// d'un seul groupe et de ses utilisateurs.
// Elle retourne un *sql.Rows qui contient les lignes du groupe donné,
// ou une erreur. L'appelant est responsable de fermer les lignes.
func fetchGroupAndUsersDataByGroupName(db *sql.DB, groupName string) (*sql.Rows, error) {
	if groupName == "" {
		return nil, fmt.Errorf("groupName cannot be empty for database query")
	}

	query := `
    SELECT g.group_name, dg.domain_name, u.username
    FROM groups g
    JOIN domain_group dg ON dg.d_id_group = g.id_group
    JOIN users_group ug ON ug.d_id_group = g.id_group
    JOIN users u ON u.id_user = ug.d_id_user
    WHERE g.group_name = ?
    ORDER BY g.group_name, dg.domain_name
    `
	// Utilisez QueryContext ou Query pour une requête simple avec un seul argument
	rows, err := db.Query(query, groupName)
	if err != nil {
		return nil, fmt.Errorf("failed to query database for group '%s': %w", groupName, err)
	}
	// L'appelant (ou processGroupRowsFromSingleQuery) est responsable de rows.Close()

	return rows, nil
}
