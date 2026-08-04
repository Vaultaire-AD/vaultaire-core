package dbpermission

import (
	"database/sql"
	"fmt"
	"vaultaire/core/database"
	guardprotected "vaultaire/core/database/guard_protected"
	"vaultaire/core/logs"
)

// Supprime une permission via son nom
func Command_DELETE_ClientPermissionByName(db *sql.DB, permissionName string) error {
	injection := database.SanitizeIdentifier(permissionName)
	if injection != nil {
		return injection
	}
	// La permission client d'administration n'est pas supprimable.
	if err := guardprotected.GuardProtectedClientPermissionDeletion(permissionName); err != nil {
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
