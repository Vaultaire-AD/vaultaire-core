package database

import (
	"vaultaire/serveur/logs"
	"database/sql"
	"fmt"
)

// Supprime un groupe via son nom
func Command_DELETE_GroupWithGroupName(db *sql.DB, groupName string) error {
	injection := SanitizeInput(groupName)
	if injection != nil {
		return injection
	}
	query := `DELETE FROM groups WHERE group_name = ?`
	_, err := db.Exec(query, groupName)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la suppression du groupe : "+err.Error())
		return fmt.Errorf("erreur lors de la suppression du groupe %s : %v", groupName, err)
	}
	logs.WriteLog("db", fmt.Sprintf("Groupe %s supprimé avec succès", groupName))
	return nil
}
