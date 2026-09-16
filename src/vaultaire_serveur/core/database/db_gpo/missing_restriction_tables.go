package dbgpo

import (
	"database/sql"
)

// missingRestrictionTables retourne les tables de restrictions absentes.
// Appelée AVANT la création des tables : c'est ce qui distingue un premier
// démarrage d'un redémarrage.
func missingRestrictionTables(db *sql.DB) (map[string]bool, error) {
	missing := map[string]bool{}
	for _, table := range restrictionTables {
		exists, err := tableExists(db, table)
		if err != nil {
			return nil, err
		}
		if !exists {
			missing[table] = true
		}
	}
	return missing, nil
}
