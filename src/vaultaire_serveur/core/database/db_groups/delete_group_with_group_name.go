package dbgroups

import (
	"database/sql"
	"fmt"
	database "vaultaire/core/database"
	guardprotected "vaultaire/core/database/guard_protected"
	"vaultaire/core/logs"
)

// Supprime un groupe via son nom
func Command_DELETE_GroupWithGroupName(db *sql.DB, groupName string) error {
	injection := database.SanitizeIdentifier(groupName)
	if injection != nil {
		return injection
	}
	// Le groupe superadmin n'est pas supprimable : voir protected.go.
	if err := guardprotected.GuardProtectedGroupDeletion(groupName); err != nil {
		return err
	}
	query := `DELETE FROM groups WHERE group_name = ?`
	_, err := db.Exec(query, groupName)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"Erreur lors de la suppression du groupe : "+err.Error())
		return fmt.Errorf("erreur lors de la suppression du groupe %s : %v", groupName, err)
	}
	logs.Write_LogCode("DEBUG", logs.CodeNone, fmt.Sprintf("database: Groupe %s supprimé avec succès", groupName))
	return nil
}
