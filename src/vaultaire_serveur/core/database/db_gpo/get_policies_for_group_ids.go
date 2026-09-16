package dbgpo

import (
	"database/sql"
	"fmt"
	"vaultaire/core/gpo"
)

// GetPoliciesForGroupIDs retourne les GPO activées, d'un scope donné, liées à au
// moins un des groupes fournis. C'est la requête de résolution : elle sera
// utilisée pour construire la politique effective d'une machine ou d'un
// utilisateur (via gpo.Resolve), une fois la partie transmission implémentée.
func GetPoliciesForGroupIDs(db *sql.DB, groupIDs []int, scope gpo.Scope) ([]gpo.Policy, error) {
	if len(groupIDs) == 0 {
		return nil, nil
	}
	if !gpo.IsValidPolicyScope(scope) {
		return nil, fmt.Errorf("scope invalide : %s", scope)
	}

	// Placeholders générés depuis la longueur du slice : les identifiants sont
	// des entiers passés en paramètres, jamais concaténés dans la requête.
	placeholders := ""
	args := make([]any, 0, len(groupIDs)+1)
	args = append(args, string(scope))
	for i, id := range groupIDs {
		if i > 0 {
			placeholders += ", "
		}
		placeholders += "?"
		args = append(args, id)
	}

	query := policySelect + ` WHERE enabled = TRUE AND scope = ? AND id_gpo IN (
		SELECT DISTINCT d_id_gpo FROM gpo_group WHERE d_id_group IN (` + placeholders + `)
	) ORDER BY gpo_name`

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("erreur de résolution des GPO par groupe : %v", err)
	}
	defer closeRows(rows)

	var policies []gpo.Policy
	for rows.Next() {
		p, err := scanPolicyRow(rows)
		if err != nil {
			return nil, err
		}
		policies = append(policies, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range policies {
		if policies[i].Modules, err = GetModulesForPolicy(db, policies[i].ID); err != nil {
			return nil, err
		}
	}
	return policies, nil
}
