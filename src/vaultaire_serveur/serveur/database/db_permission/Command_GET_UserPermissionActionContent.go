package db_permission

import (
	"database/sql"
	"fmt"
)

// GetUserPermissionActions récupère toutes les actions d'une permission via son ID
// Command_GET_UserPermissionAction récupère le contenu d'une action précise
func Command_GET_UserPermissionAction(db *sql.DB, id int64, action string) (string, error) {
	// ⚠️ Vérification de l'argument "action" pour éviter l'injection SQL
	validActions := map[string]bool{
		"none": true, "web_admin": true, "auth": true, "compare": true,
		"search": true, "can_read": true, "can_write": true,
		"api_read_permission": true, "api_write_permission": true,
	}

	if !validActions[action] {
		return "", fmt.Errorf("action '%s' invalide", action)
	}

	// Construction de la requête dynamiquement
	query := fmt.Sprintf(`SELECT %s FROM user_permission WHERE id_user_permission = ? LIMIT 1`, action)

	var value string
	err := db.QueryRow(query, id).Scan(&value)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("aucune permission trouvée avec l'id %d", id)
		}
		return "", err
	}

	return value, nil
}
