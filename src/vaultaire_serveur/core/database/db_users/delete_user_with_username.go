package dbusers

import (
	"database/sql"
	"fmt"
	database "vaultaire/core/database"
	guardprotected "vaultaire/core/database/guard_protected"
	"vaultaire/core/logs"
)

// Command_Remove_User supprime un utilisateur et toutes ses relations
func Command_DELETE_UserWithUsername(db *sql.DB, username string) error {
	injection := database.SanitizeIdentifier(username)
	if injection != nil {
		return injection
	}
	// Le compte d'amorçage n'est pas supprimable : voir protected.go.
	if err := guardprotected.GuardProtectedUserDeletion(username); err != nil {
		return err
	}
	// Vérifier si l'utilisateur existe
	userID, found, err := database.LookupUserID(db, username)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la récupération de l'utilisateur : "+err.Error())
		return fmt.Errorf("erreur lors de la récupération de l'utilisateur : %v", err)
	}
	if !found {
		logs.Write_LogCode("WARNING", logs.CodeDBUserNotFound, fmt.Sprintf("database: Utilisateur %s introuvable", username))
		return fmt.Errorf("utilisateur %s introuvable", username)
	}

	// Supprimer l'utilisateur (les contraintes ON DELETE CASCADE s'occupent du reste)
	queryDelete := `DELETE FROM users WHERE id_user = ?`
	_, err = db.Exec(queryDelete, userID)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la suppression de l'utilisateur : "+err.Error())
		return fmt.Errorf("erreur lors de la suppression de l'utilisateur : %v", err)
	}

	logs.Write_LogCode("DEBUG", logs.CodeNone, fmt.Sprintf("database: Utilisateur %s supprimé avec succès", username))
	return nil
}
