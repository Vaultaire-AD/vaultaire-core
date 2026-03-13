package dnsdatabase

import (
	"database/sql"
	"fmt"
)

// AddPTRRecord ajoute une entrée PTR dans la table ptr_records
func AddPTRRecord(db *sql.DB, ip string, fqdn string) error {
	if db == nil {
		return fmt.Errorf("la base de données est nulle")
	}

	// Vérifier si un PTR existe déjà pour cette IP
	var existingName string
	queryCheck := `SELECT name FROM ptr_records WHERE ip = ?`
	err := db.QueryRow(queryCheck, ip).Scan(&existingName)
	if err == nil {
		return fmt.Errorf("un enregistrement PTR existe déjà pour %s → %s", ip, existingName)
	} else if err != sql.ErrNoRows {
		return fmt.Errorf("erreur lors de la vérification de l'existence du PTR : %v", err)
	}

	// Insérer le nouvel enregistrement
	queryInsert := `INSERT INTO ptr_records (ip, name) VALUES (?, ?)`
	_, err = db.Exec(queryInsert, ip, fqdn)
	if err != nil {
		return fmt.Errorf("erreur insertion ptr_record : %v", err)
	}
	return nil
}
