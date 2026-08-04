package dbgroups

import (
	"database/sql"
	"fmt"
	database "vaultaire/core/database"
	"vaultaire/core/logs"
)

func Command_ADD_UserToGroup(db *sql.DB, username, groupName string) error {
	injection := database.SanitizeIdentifier(username, groupName)
	if injection != nil {
		return injection
	}
	// Vérifier si l'utilisateur existe
	userID, found, err := database.LookupUserID(db, username)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la récupération de l'utilisateur : "+err.Error())
		return fmt.Errorf("erreur lors de la récupération de l'utilisateur : %v", err)
	}
	if !found {
		return fmt.Errorf("utilisateur avec le nom d'utilisateur %s introuvable", username)
	}

	// Vérifier si le groupe existe
	groupID, found, err := database.LookupGroupID(db, groupName)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la récupération du groupe : "+err.Error())
		return fmt.Errorf("erreur lors de la récupération du groupe : %v", err)
	}
	if !found {
		return fmt.Errorf("groupe avec le nom %s introuvable", groupName)
	}

	// Vérifier si l'utilisateur est déjà dans ce groupe
	already, err := userGroupLinkExists(db, userID, groupID)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la vérification de l'utilisateur dans le groupe : "+err.Error())
		return fmt.Errorf("erreur lors de la vérification de l'utilisateur dans le groupe : %v", err)
	}

	// Si l'utilisateur est déjà dans ce groupe, on ne fait rien
	if already {
		return fmt.Errorf("l'utilisateur %s est déjà membre du groupe %s", username, groupName)
	}

	// Ajouter l'utilisateur au groupe
	queryAdd := `INSERT INTO users_group (d_id_user, d_id_group) VALUES (?, ?)`
	_, err = db.Exec(queryAdd, userID, groupID)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de l'ajout de l'utilisateur au groupe : "+err.Error())
		return fmt.Errorf("erreur lors de l'ajout de l'utilisateur au groupe : %v", err)
	}

	return nil
}
