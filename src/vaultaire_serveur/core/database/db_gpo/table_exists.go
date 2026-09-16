package dbgpo

import (
	"database/sql"
	"fmt"
)

// tableExists indique si une table existe dans la base courante.
func tableExists(db *sql.DB, table string) (bool, error) {
	var count int
	err := db.QueryRow(
		`SELECT COUNT(*) FROM information_schema.tables
		 WHERE table_schema = DATABASE() AND table_name = ?`, table,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("vérification de l'existence de %s impossible : %v", table, err)
	}
	return count > 0, nil
}
