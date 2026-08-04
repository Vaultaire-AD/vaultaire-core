package dbgpo

import (
	"database/sql"
	"fmt"
	"vaultaire/core/logs"
)

// createRestrictionTables crée les tables de restrictions.
func createRestrictionTables(db *sql.DB) error {
	for _, ddl := range restrictionTablesDDL {
		if _, err := db.Exec(ddl); err != nil {
			logs.Write_LogCode("ERROR", logs.CodeDBGeneric, "gpo: création des tables de restrictions échouée : "+err.Error())
			return fmt.Errorf("gpo: création des tables de restrictions échouée : %v", err)
		}
	}
	return nil
}
