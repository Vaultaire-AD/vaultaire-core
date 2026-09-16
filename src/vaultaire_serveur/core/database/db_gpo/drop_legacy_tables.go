package dbgpo

import (
	"database/sql"
	"fmt"
	"vaultaire/core/logs"
)

// DropLegacyTables supprime les tables de l'ancien modèle GPO si elles sont
// encore présentes. Idempotent : sans effet sur une base déjà migrée.
func DropLegacyTables(db *sql.DB) error {
	for _, table := range legacyTablesToDrop {
		if _, err := db.Exec("DROP TABLE IF EXISTS " + table); err != nil {
			logs.Write_LogCode("ERROR", logs.CodeDBGeneric, "gpo: suppression de la table héritée "+table+" échouée : "+err.Error())
			return fmt.Errorf("gpo: suppression de la table héritée %s échouée : %v", table, err)
		}
	}
	return nil
}
