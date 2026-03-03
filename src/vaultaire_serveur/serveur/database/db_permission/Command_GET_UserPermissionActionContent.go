package db_permission

import (
	"database/sql"
	"fmt"
)

// Command_GET_UserPermissionAction récupère le contenu d'une action pour une permission (par ID).
// Actions legacy (none, web_admin, auth, compare, search) : colonne user_permission.
// Actions RBAC (catégorie:action:objet) : table user_permission_action.
func Command_GET_UserPermissionAction(db *sql.DB, id int64, action string) (string, error) {
	if legacyColumns[action] {
		query := fmt.Sprintf("SELECT %s FROM user_permission WHERE id_user_permission = ? LIMIT 1", action)
		var value string
		err := db.QueryRow(query, id).Scan(&value)
		if err != nil {
			return "", err
		}
		return value, nil
	}

	var value string
	err := db.QueryRow(
		"SELECT value FROM user_permission_action WHERE id_user_permission = ? AND action_key = ?",
		id, action,
	).Scan(&value)
	if err == sql.ErrNoRows {
		return "nil", nil
	}
	if err != nil {
		return "", err
	}
	return value, nil
}
