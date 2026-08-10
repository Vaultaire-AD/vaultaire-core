package dbpermission

import (
	"database/sql"
	"fmt"
	"vaultaire/core/logs"
)

// GetPermissionContent récupère le contenu d'une action pour un groupe donné.
// Actions legacy (none, web_admin, auth, compare, search) : colonnes user_permission.
// Actions RBAC (catégorie:action:objet) : table user_permission_action.
func GetPermissionContent(db *sql.DB, groupID int, action string) (string, error) {
	var permissionID int
	if err := db.QueryRow("SELECT d_id_user_permission FROM group_user_permission WHERE d_id_group = ?", groupID).Scan(&permissionID); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+fmt.Sprintf("Erreur récupération user_permission pour groupe %d: %v", groupID, err))
		return "", fmt.Errorf("erreur récupération user_permission pour le groupe %d: %v", groupID, err)
	}

	if legacyColumns[action] {
		var content string
		query := fmt.Sprintf("SELECT %s FROM user_permission WHERE id_user_permission = ?", action)
		if err := db.QueryRow(query, permissionID).Scan(&content); err != nil {
			logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+fmt.Sprintf("Erreur récupération action '%s' permission %d: %v", action, permissionID, err))
			return "", fmt.Errorf("erreur récupération action '%s': %v", action, err)
		}
		return content, nil
	}

	// int -> int64 : les deux appelants de actionValue ne s'accordent pas sur le
	// type de l'identifiant, héritage des deux époques du paquet.
	value, err := actionValue(db, int64(permissionID), action)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+fmt.Sprintf("Erreur récupération action_key '%s' permission %d: %v", action, permissionID, err))
		return "", err
	}
	return value, nil
}
