package dbgpo

import (
	"database/sql"
	"fmt"
	"vaultaire/core/gpo"
)

// GetPoliciesByScope retourne les GPO d'un scope donné, modules chargés.
func GetPoliciesByScope(db *sql.DB, scope gpo.Scope) ([]gpo.Policy, error) {
	if !gpo.IsValidPolicyScope(scope) {
		return nil, fmt.Errorf("scope invalide : %s", scope)
	}
	rows, err := db.Query(policySelect+` WHERE scope = ? ORDER BY gpo_name`, string(scope))
	if err != nil {
		return nil, fmt.Errorf("erreur de lecture des GPO de scope %s : %v", scope, err)
	}
	defer closeRows(rows)

	var out []gpo.Policy
	for rows.Next() {
		p, err := scanPolicyRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if out[i].Modules, err = GetModulesForPolicy(db, out[i].ID); err != nil {
			return nil, err
		}
	}
	return out, nil
}
