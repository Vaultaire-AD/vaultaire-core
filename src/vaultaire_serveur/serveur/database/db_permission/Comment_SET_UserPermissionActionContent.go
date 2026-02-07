package db_permission

import (
	"vaultaire/serveur/logs"
	"database/sql"
	"fmt"
)

// Command_SET_UserPermissionAction met à jour le contenu d'une action précise
func Command_SET_UserPermissionAction(db *sql.DB, id int64, action string, newValue string) error {
	// ⚠️ Vérification de l'argument "action" pour éviter l'injection SQL
	validActions := map[string]bool{
		"none": true, "web_admin": true, "auth": true, "compare": true,
		"search": true, "can_read": true, "can_write": true,
		"api_read_permission": true, "api_write_permission": true,
	}

	if !validActions[action] {
		logs.WriteLog("db", "action invalide : "+action)
		return fmt.Errorf("action '%s' invalide", action)
	}

	// Construction dynamique de la requête
	query := fmt.Sprintf(`UPDATE user_permission SET %s = ? WHERE id_user_permission = ?`, action)

	// Exécution
	_, err := db.Exec(query, newValue, id)
	if err != nil {
		logs.WriteLog("db", fmt.Sprintf("échec de la mise à jour de l'action '%s' pour la permission %d : %v", action, id, err))
		return fmt.Errorf("erreur lors de la mise à jour de l'action '%s' pour la permission %d : %v", action, id, err)
	}

	return nil
}
