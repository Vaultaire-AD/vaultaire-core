package database

import (
	"DUCKY/serveur/logs"
	"database/sql"
	"fmt"
)

// Command_Remove_UserFromGroup supprime un utilisateur d'un groupe
func Command_Remove_UserFromGroup(db *sql.DB, username, groupName string) error {
	injection := SanitizeInput(username, groupName)
	if injection != nil {
		return injection
	}
	// Vérifier si l'utilisateur existe
	var userID int
	queryUser := `SELECT id_user FROM users WHERE username = ?`
	err := db.QueryRow(queryUser, username).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows {
			logs.WriteLog("db", fmt.Sprintf("Utilisateur %s introuvable", username))
			return fmt.Errorf("utilisateur %s introuvable", username)
		}
		logs.WriteLog("db", fmt.Sprintf("Erreur lors de la récupération de l'utilisateur : %v", err))
		return fmt.Errorf("erreur lors de la récupération de l'utilisateur : %v", err)
	}

	// Vérifier si le groupe existe
	var groupID int
	queryGroup := `SELECT id_group FROM groups WHERE group_name = ?`
	err = db.QueryRow(queryGroup, groupName).Scan(&groupID)
	if err != nil {
		if err == sql.ErrNoRows {
			logs.WriteLog("db", fmt.Sprintf("Groupe %s introuvable", groupName))
			return fmt.Errorf("groupe %s introuvable", groupName)
		}
		logs.WriteLog("db", fmt.Sprintf("Erreur lors de la récupération du groupe : %v", err))
		return fmt.Errorf("erreur lors de la récupération du groupe : %v", err)
	}

	// Vérifier si l'utilisateur est dans ce groupe
	var count int
	queryCheck := `SELECT COUNT(*) FROM users_group WHERE d_id_user = ? AND d_id_group = ?`
	err = db.QueryRow(queryCheck, userID, groupID).Scan(&count)
	if err != nil {
		logs.WriteLog("db", fmt.Sprintf("Erreur lors de la vérification de l'utilisateur dans le groupe : %v", err))
		return fmt.Errorf("erreur lors de la vérification de l'utilisateur dans le groupe : %v", err)
	}

	if count == 0 {
		logs.WriteLog("db", fmt.Sprintf("L'utilisateur %s ne fait pas partie du groupe %s", username, groupName))
		return fmt.Errorf("l'utilisateur %s ne fait pas partie du groupe %s", username, groupName)
	}

	// Supprimer l'utilisateur du groupe
	queryRemove := `DELETE FROM users_group WHERE d_id_user = ? AND d_id_group = ?`
	_, err = db.Exec(queryRemove, userID, groupID)
	if err != nil {
		logs.WriteLog("db", fmt.Sprintf("Erreur lors de la suppression de l'utilisateur du groupe : %v", err))
		return fmt.Errorf("erreur lors de la suppression de l'utilisateur du groupe : %v", err)
	}

	// Log de succès
	logs.WriteLog("db", fmt.Sprintf("Utilisateur %s retiré du groupe %s", username, groupName))

	return nil
}
