package dbgpo

import (
	"database/sql"
	"fmt"
	"vaultaire/core/database"
)

// GetPolicyIDByName résout l'identifiant d'une GPO depuis son nom.
func GetPolicyIDByName(db *sql.DB, name string) (int, error) {
	if err := database.SanitizeIdentifier(name); err != nil {
		return 0, err
	}
	var id int
	err := db.QueryRow(`SELECT id_gpo FROM gpo WHERE gpo_name = ?`, name).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, fmt.Errorf("GPO %s introuvable", name)
	}
	if err != nil {
		return 0, fmt.Errorf("erreur de lecture de la GPO %s : %v", name, err)
	}
	return id, nil
}
