package dbgpo

import (
	"database/sql"
	"fmt"
	"vaultaire/core/database"
	"vaultaire/core/gpo"
)

// GetPolicyByName retourne une GPO complète : métadonnées, modules triés dans
// leur ordre d'application, et noms des groupes auxquels elle est liée.
func GetPolicyByName(db *sql.DB, name string) (*gpo.Policy, error) {
	if err := database.SanitizeIdentifier(name); err != nil {
		return nil, err
	}
	row := db.QueryRow(policySelect+` WHERE gpo_name = ?`, name)
	p, err := scanPolicyRow(row)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("GPO %s introuvable", name)
	}
	if err != nil {
		return nil, fmt.Errorf("erreur de lecture de la GPO %s : %v", name, err)
	}

	modules, err := GetModulesForPolicy(db, p.ID)
	if err != nil {
		return nil, err
	}
	p.Modules = modules

	groups, err := GetGroupsForPolicy(db, p.ID)
	if err != nil {
		return nil, err
	}
	p.Groups = groups
	return &p, nil
}
