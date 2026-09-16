package dbgpo

import (
	"database/sql"
	"fmt"
	"vaultaire/core/gpo"
)

// GetPolicyByID retourne une GPO complète depuis son identifiant.
func GetPolicyByID(db *sql.DB, id int) (*gpo.Policy, error) {
	row := db.QueryRow(policySelect+` WHERE id_gpo = ?`, id)
	p, err := scanPolicyRow(row)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("GPO %d introuvable", id)
	}
	if err != nil {
		return nil, fmt.Errorf("erreur de lecture de la GPO %d : %v", id, err)
	}
	if p.Modules, err = GetModulesForPolicy(db, p.ID); err != nil {
		return nil, err
	}
	if p.Groups, err = GetGroupsForPolicy(db, p.ID); err != nil {
		return nil, err
	}
	return &p, nil
}
