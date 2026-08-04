package dbgpo

import (
	"database/sql"
	"vaultaire/core/database"
)

// PolicyExists indique si une GPO de ce nom existe.
func PolicyExists(db *sql.DB, name string) bool {
	if err := database.SanitizeIdentifier(name); err != nil {
		return false
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM gpo WHERE gpo_name = ?`, name).Scan(&count); err != nil {
		return false
	}
	return count > 0
}
