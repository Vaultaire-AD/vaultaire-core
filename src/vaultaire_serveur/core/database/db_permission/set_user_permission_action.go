package dbpermission

import (
	"database/sql"
	"fmt"
	guardprotected "vaultaire/core/database/guard_protected"
	"vaultaire/core/logs"
)

// Command_SET_UserPermissionAction met à jour le contenu d'une action.
// Actions legacy : UPDATE user_permission. Actions RBAC : INSERT/UPDATE user_permission_action.
func Command_SET_UserPermissionAction(db *sql.DB, id int64, action string, newValue string) error {
	// La permission d'amorçage n'est pas modifiable, y compris de l'intérieur.
	// Le contrôle porte sur l'identifiant reçu, pas sur un nom passé par
	// l'appelant : c'est la seule façon de couvrir tous les chemins, y compris
	// ceux qui ne connaissent que l'ID.
	if name, err := getPermissionNameByID(db, id); err == nil {
		if guardErr := guardprotected.GuardProtectedPermissionContent(name, action); guardErr != nil {
			return guardErr
		}
	}

	if legacyColumns[action] {
		query := fmt.Sprintf("UPDATE user_permission SET %s = ? WHERE id_user_permission = ?", action)
		_, err := db.Exec(query, newValue, id)
		if err != nil {
			logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+fmt.Sprintf("SET legacy action '%s' permission %d: %v", action, id, err))
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
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+fmt.Sprintf("SET action_key '%s' permission %d: %v", action, id, err))
		return err
	}
	return nil
}
