package dbpermission

import (
	"database/sql"
	"fmt"
	"vaultaire/core/database"
	guardprotected "vaultaire/core/database/guard_protected"
	"vaultaire/core/logs"
)

func Command_DELETE_UserPermissionByName(db *sql.DB, permissionName string) error {
	injection := database.SanitizeIdentifier(permissionName)
	if injection != nil {
		return injection
	}
	// La permission complète du groupe superadmin n'est pas supprimable :
	// voir core/database/protected.go.
	if err := guardprotected.GuardProtectedUserPermissionDeletion(permissionName); err != nil {
		return err
	}
	query := `DELETE FROM user_permission WHERE name = ?`
	_, err := db.Exec(query, permissionName)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"Erreur lors de la suppression de la permission utilisateur : "+err.Error())
		return fmt.Errorf("erreur lors de la suppression de la permission utilisateur %s : %v", permissionName, err)
	}
	logs.Write_LogCode("DEBUG", logs.CodeNone, fmt.Sprintf("database: Permission utilisateur %s supprimée avec succès", permissionName))
	return nil
}
