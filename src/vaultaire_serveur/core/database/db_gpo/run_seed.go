package dbgpo

import (
	"database/sql"
	"fmt"
	"strings"
	"vaultaire/core/gpo"
	"vaultaire/core/logs"
)

// runSeed exécute les instructions de peuplement visant les tables indiquées.
//
// tables nil signifie « toutes » : utilisé par la réinitialisation, qui a purgé
// les tables au préalable.
func runSeed(db *sql.DB, tables map[string]bool) error {
	statements, err := loadSeedStatements()
	if err != nil {
		return err
	}

	applied := 0
	perTable := map[string]int{}
	for _, stmt := range statements {
		if tables != nil && !tables[stmt.Table] {
			continue
		}
		if _, err := db.Exec(stmt.SQL); err != nil {
			logs.Write_LogCode("ERROR", logs.CodeDBGeneric,
				"gpo: peuplement de "+stmt.Table+" échoué : "+err.Error())
			return fmt.Errorf("gpo: peuplement de %s échoué : %v", stmt.Table, err)
		}
		applied++
		perTable[stmt.Table]++
	}

	if applied > 0 {
		var parts []string
		for _, table := range restrictionTables {
			if n := perTable[table]; n > 0 {
				parts = append(parts, fmt.Sprintf("%s: %d", table, n))
			}
		}
		logs.Write_Log("INFO", "gpo: peuplement initial des restrictions appliqué ("+strings.Join(parts, ", ")+")")
		gpo.InvalidateRestrictionCache()
	}
	return nil
}
