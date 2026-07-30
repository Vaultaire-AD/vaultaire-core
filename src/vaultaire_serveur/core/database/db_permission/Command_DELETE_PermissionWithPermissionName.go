package db_permission

import (
	"database/sql"
	"fmt"
	"vaultaire/core/database"
	"vaultaire/core/logs"
)

// Supprime une permission via son nom
func Command_DELETE_ClientPermissionByName(db *sql.DB, permissionName string) error {
	injection := database.SanitizeInput(permissionName)
	if injection != nil {
		return injection
	}
	// La permission client d'administration n'est pas supprimable.
	if err := database.GuardProtectedClientPermissionDeletion(permissionName); err != nil {
		return err
	}
	query := `DELETE FROM client_permission WHERE name_permission = ?`
	_, err := db.Exec(query, permissionName)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la suppression de la permission client : "+err.Error())
		return fmt.Errorf("erreur lors de la suppression de la permission client %s : %v", permissionName, err)
	}
	logs.Write_LogCode("DEBUG", logs.CodeNone, fmt.Sprintf("database: Permission client %s supprimée avec succès", permissionName))
	return nil
}

func Command_DELETE_UserPermissionByName(db *sql.DB, permissionName string) error {
	injection := database.SanitizeInput(permissionName)
	if injection != nil {
		return injection
	}
	// La permission complète du groupe superadmin n'est pas supprimable :
	// voir core/database/protected.go.
	if err := database.GuardProtectedUserPermissionDeletion(permissionName); err != nil {
		return err
	}
	query := `DELETE FROM user_permission WHERE name = ?`
	_, err := db.Exec(query, permissionName)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la suppression de la permission utilisateur : "+err.Error())
		return fmt.Errorf("erreur lors de la suppression de la permission utilisateur %s : %v", permissionName, err)
	}
	logs.Write_LogCode("DEBUG", logs.CodeNone, fmt.Sprintf("database: Permission utilisateur %s supprimée avec succès", permissionName))
	return nil
}
