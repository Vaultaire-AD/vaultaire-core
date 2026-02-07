package db_permission

import (
	"vaultaire/serveur/database"
	"vaultaire/serveur/logs"
	"database/sql"
)

// Command_GET_UserPermissionNamesByUsername returns permission names the user gets through their groups.
func Command_GET_UserPermissionNamesByUsername(db *sql.DB, username string) ([]string, error) {
	if err := database.SanitizeInput(username); err != nil {
		return nil, err
	}
	query := `
		SELECT DISTINCT p.name
		FROM user_permission p
		INNER JOIN group_user_permission gup ON p.id_user_permission = gup.d_id_user_permission
		INNER JOIN users_group ug ON gup.d_id_group = ug.d_id_group
		INNER JOIN users u ON ug.d_id_user = u.id_user
		WHERE u.username = ?
	`
	rows, err := db.Query(query, username)
	if err != nil {
		logs.WriteLog("db", "UserPermissionNamesByUsername: "+err.Error())
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		names = append(names, n)
	}
	return names, rows.Err()
}
