package database

import (
	"DUCKY/serveur/logs"
	"database/sql"
	"strings"
)

func FindGroupsByUserInDomainTree(db *sql.DB, username string, baseDomain string) ([]string, error) {
	injection := SanitizeInput(username, baseDomain)
	if injection != nil {
		return nil, injection
	}
	query := `
		SELECT g.group_name, dg.domain_name
		FROM users u
		JOIN users_group ug ON u.id_user = ug.d_id_user
		JOIN groups g ON g.id_group = ug.d_id_group
		JOIN domain_group dg ON dg.d_id_group = g.id_group
		WHERE u.username = ?;
	`

	rows, err := db.Query(query, username)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := rows.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
		}
	}()

	var groups []string
	for rows.Next() {
		var groupName, groupDomain string
		if err := rows.Scan(&groupName, &groupDomain); err != nil {
			return nil, err
		}

		// Vérifie si groupDomain est une sous-forêt de baseDomain
		if isSubDomain(groupDomain, baseDomain) {
			groups = append(groups, groupName)
		}
	}

	return groups, nil
}

func isSubDomain(child, parent string) bool {
	return strings.HasSuffix(child, parent)
}
