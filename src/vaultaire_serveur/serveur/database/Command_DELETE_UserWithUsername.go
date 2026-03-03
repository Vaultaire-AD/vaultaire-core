package database

import (
	"vaultaire/serveur/logs"
	"database/sql"
	"fmt"
)

// Command_Remove_User supprime un utilisateur et toutes ses relations
func Command_DELETE_UserWithUsername(db *sql.DB, username string) error {
	injection := SanitizeInput(username)
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
		logs.WriteLog("db", "Erreur lors de la récupération de l'utilisateur : "+err.Error())
		return fmt.Errorf("erreur lors de la récupération de l'utilisateur : %v", err)
	}

	// Supprimer l'utilisateur (les contraintes ON DELETE CASCADE s'occupent du reste)
	queryDelete := `DELETE FROM users WHERE id_user = ?`
	_, err = db.Exec(queryDelete, userID)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la suppression de l'utilisateur : "+err.Error())
		return fmt.Errorf("erreur lors de la suppression de l'utilisateur : %v", err)
	}

	logs.WriteLog("db", fmt.Sprintf("Utilisateur %s supprimé avec succès", username))
	return nil
}
