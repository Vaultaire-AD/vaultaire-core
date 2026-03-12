package db_permission

import (
	"database/sql"
	"fmt"
	"vaultaire/serveur/logs"
)

// colonnes legacy (table user_permission)
var legacyColumns = map[string]bool{
	"none": true, "web_admin": true, "auth": true, "compare": true, "search": true,
}

// GetPermissionContent récupère le contenu d'une action pour un groupe donné.
// Actions legacy (none, web_admin, auth, compare, search) : colonnes user_permission.
// Actions RBAC (catégorie:action:objet) : table user_permission_action.
func GetPermissionContent(db *sql.DB, groupID int, action string) (string, error) {
	var permissionID int
	if err := db.QueryRow("SELECT d_id_user_permission FROM group_user_permission WHERE d_id_group = ?", groupID).Scan(&permissionID); err != nil {
		logs.WriteLog("db", fmt.Sprintf("Erreur récupération user_permission pour groupe %d: %v", groupID, err))
		return "", fmt.Errorf("erreur récupération user_permission pour le groupe %d: %v", groupID, err)
	}

	if legacyColumns[action] {
		var content string
		query := fmt.Sprintf("SELECT %s FROM user_permission WHERE id_user_permission = ?", action)
		if err := db.QueryRow(query, permissionID).Scan(&content); err != nil {
			logs.WriteLog("db", fmt.Sprintf("Erreur récupération action '%s' permission %d: %v", action, permissionID, err))
			return "", fmt.Errorf("erreur récupération action '%s': %v", action, err)
		}
		return content, nil
	}

	var value string
	err := db.QueryRow(
		"SELECT value FROM user_permission_action WHERE id_user_permission = ? AND action_key = ?",
		permissionID, action,
	).Scan(&value)
	if err == sql.ErrNoRows {
		return "nil", nil
	}
	if err != nil {
		logs.WriteLog("db", fmt.Sprintf("Erreur récupération action_key '%s' permission %d: %v", action, permissionID, err))
		return "", err
	}
	return value, nil
}
