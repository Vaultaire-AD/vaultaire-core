package database

import (
	"database/sql"
	"fmt"
	"vaultaire/core/logs"
)

// Supprime un groupe via son nom
func Command_DELETE_GroupWithGroupName(db *sql.DB, groupName string) error {
	injection := SanitizeInput(groupName)
	if injection != nil {
		return injection
	}
	// Le groupe superadmin n'est pas supprimable : voir protected.go.
	if err := GuardProtectedGroupDeletion(groupName); err != nil {
		return err
	}
	query := `DELETE FROM groups WHERE group_name = ?`
	_, err := db.Exec(query, groupName)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la suppression du groupe : "+err.Error())
		return fmt.Errorf("erreur lors de la suppression du groupe %s : %v", groupName, err)
	}
	logs.Write_LogCode("DEBUG", logs.CodeNone, fmt.Sprintf("database: Groupe %s supprimé avec succès", groupName))
	return nil
}
