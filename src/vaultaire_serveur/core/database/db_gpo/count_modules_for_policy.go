package dbgpo

import (
	"database/sql"
	"fmt"
)

// CountModulesForPolicy compte les modules d'une GPO.
func CountModulesForPolicy(db *sql.DB, policyID int) (int, error) {
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM gpo_module WHERE d_id_gpo = ?`, policyID).Scan(&count); err != nil {
		return 0, fmt.Errorf("comptage des modules de la GPO %d impossible : %v", policyID, err)
	}
	return count, nil
}
