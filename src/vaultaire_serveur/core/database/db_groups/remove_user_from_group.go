package dbgroups

import (
	"database/sql"
	"fmt"
	database "vaultaire/core/database"
	guardprotected "vaultaire/core/database/guard_protected"
	"vaultaire/core/logs"
)

// Command_Remove_UserFromGroup supprime un utilisateur d'un groupe
func Command_Remove_UserFromGroup(db *sql.DB, username, groupName string) error {
	injection := database.SanitizeIdentifier(username, groupName)
	if injection != nil {
		return injection
	}
	// Retirer vaultaire du groupe vaultaire lui ôterait toutes ses permissions :
	// l'effet est équivalent à une suppression du compte. Voir protected.go.
	if err := guardprotected.GuardProtectedMembership(username, groupName); err != nil {
		return err
	}
	// Vérifier si l'utilisateur existe
	userID, found, err := database.LookupUserID(db, username)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+fmt.Sprintf("Erreur lors de la récupération de l'utilisateur : %v", err))
		return fmt.Errorf("erreur lors de la récupération de l'utilisateur : %v", err)
	}
	if !found {
		logs.Write_LogCode("WARNING", logs.CodeDBUserNotFound, fmt.Sprintf("database: Utilisateur %s introuvable", username))
		return fmt.Errorf("utilisateur %s introuvable", username)
	}

	// Vérifier si le groupe existe
	groupID, found, err := database.LookupGroupID(db, groupName)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+fmt.Sprintf("Erreur lors de la récupération du groupe : %v", err))
		return fmt.Errorf("erreur lors de la récupération du groupe : %v", err)
	}
	if !found {
		logs.Write_LogCode("WARNING", logs.CodeDBGeneric, fmt.Sprintf("database: Groupe %s introuvable", groupName))
		return fmt.Errorf("groupe %s introuvable", groupName)
	}

	// Vérifier si l'utilisateur est dans ce groupe
	member, err := userGroupLinkExists(db, userID, groupID)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+fmt.Sprintf("Erreur lors de la vérification de l'utilisateur dans le groupe : %v", err))
		return fmt.Errorf("erreur lors de la vérification de l'utilisateur dans le groupe : %v", err)
	}

	if !member {
		logs.Write_LogCode("WARNING", logs.CodeDBGeneric, fmt.Sprintf("database: L'utilisateur %s ne fait pas partie du groupe %s", username, groupName))
		return fmt.Errorf("l'utilisateur %s ne fait pas partie du groupe %s", username, groupName)
	}

	// Supprimer l'utilisateur du groupe
	queryRemove := `DELETE FROM users_group WHERE d_id_user = ? AND d_id_group = ?`
	_, err = db.Exec(queryRemove, userID, groupID)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+fmt.Sprintf("Erreur lors de la suppression de l'utilisateur du groupe : %v", err))
		return fmt.Errorf("erreur lors de la suppression de l'utilisateur du groupe : %v", err)
	}

	// Log de succès
	logs.Write_LogCode("DEBUG", logs.CodeNone, fmt.Sprintf("database: Utilisateur %s retiré du groupe %s", username, groupName))

	return nil
}
