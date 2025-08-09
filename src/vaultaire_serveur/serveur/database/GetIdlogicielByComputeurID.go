package database

import (
	"database/sql"
	"fmt"
)

func GetIdLogicielByComputeurID(db *sql.DB, computeurID string) (string, error) {
	injection := SanitizeInput(computeurID)
	if injection != nil {
		return "", injection
	}
	var idLogiciel string
	query := "SELECT id_logiciel FROM id_logiciels WHERE computeur_id = ? LIMIT 1"

	// Execute the query and store the result in idLogiciel
	err := db.QueryRow(query, computeurID).Scan(&idLogiciel)
	if err != nil {
		if err == sql.ErrNoRows {
			// No row found for the given computeur_id
			return "", fmt.Errorf("no id_logiciel found for computeur_id: %s", computeurID)
		}
		// Handle other possible errors
		return "", err
	}

	// Return the id_logiciel
	return idLogiciel, nil
}
