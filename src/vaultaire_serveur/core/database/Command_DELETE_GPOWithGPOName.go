package database

import (
	"database/sql"
	"fmt"
	"vaultaire/core/logs"
)

func Command_DELETE_GPOWithGPOName(db *sql.DB, gpoName string) error {
	injection := SanitizeInput(gpoName)
	if injection != nil {
		return injection
	}
	query := `DELETE FROM linux_gpo_distributions WHERE gpo_name = ?`
	_, err := db.Exec(query, gpoName)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la suppression de la gpo : "+err.Error())
		return fmt.Errorf("erreur lors de la suppression de la gpo %s : %v", gpoName, err)
	}
	logs.Write_LogCode("DEBUG", logs.CodeNone, fmt.Sprintf("database: gpo %s supprimé avec succès", gpoName))
	return nil
}
