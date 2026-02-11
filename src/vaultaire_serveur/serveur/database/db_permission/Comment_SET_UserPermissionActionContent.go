package db_permission

import (
	"database/sql"
	"fmt"
	"vaultaire/serveur/logs"
)

// Command_SET_UserPermissionAction met à jour le contenu d'une action.
// Actions legacy : UPDATE user_permission. Actions RBAC : INSERT/UPDATE user_permission_action.
func Command_SET_UserPermissionAction(db *sql.DB, id int64, action string, newValue string) error {
	if legacyColumns[action] {
		query := fmt.Sprintf("UPDATE user_permission SET %s = ? WHERE id_user_permission = ?", action)
		_, err := db.Exec(query, newValue, id)
		if err != nil {
			logs.WriteLog("db", fmt.Sprintf("SET legacy action '%s' permission %d: %v", action, id, err))
			return err
		}
		return nil
	}

	_, err := db.Exec(
		`INSERT INTO user_permission_action (id_user_permission, action_key, value) VALUES (?, ?, ?)
		 ON DUPLICATE KEY UPDATE value = VALUES(value)`,
		id, action, newValue,
	)
	if err != nil {
		logs.WriteLog("db", fmt.Sprintf("SET action_key '%s' permission %d: %v", action, id, err))
		return err
	}
	return nil
}
