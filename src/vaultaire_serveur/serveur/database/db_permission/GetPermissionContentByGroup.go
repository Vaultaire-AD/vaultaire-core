package db_permission

import (
	"DUCKY/serveur/logs"
	"database/sql"
	"fmt"
)

// GetPermissionContent récupère le contenu d'une action pour un groupe donné
func GetPermissionContent(db *sql.DB, groupID int, action string) (string, error) {
	var permissionID int
	var content string

	// 1. Récupérer l'id_user_permission à partir du groupID
	err := db.QueryRow("SELECT d_id_user_permission FROM group_user_permission WHERE d_id_group = ?", groupID).Scan(&permissionID)
	if err != nil {
		logs.WriteLog("db", fmt.Sprintf("Erreur lors de la récupération du user_permission pour le groupe %d: %v", groupID, err))
		return "", fmt.Errorf("erreur lors de la récupération du user_permission pour le groupe %d: %v", groupID, err)
	}

	// 2. Construire dynamiquement la requête pour récupérer le champ lié à l'action
	query := fmt.Sprintf("SELECT %s FROM user_permission_test WHERE id_user_permission_scope = ?", action)

	// 3. Exécuter la requête
	err = db.QueryRow(query, permissionID).Scan(&content)
	if err != nil {
		logs.WriteLog("db", fmt.Sprintf("Erreur lors de la récupération de l'action '%s' pour le user_permission %d: %v", action, permissionID, err))
		return "", fmt.Errorf("erreur lors de la récupération de l'action '%s' pour le user_permission %d: %v", action, permissionID, err)
	}

	return content, nil
}
