package dbgpo

import (
	"database/sql"
	"fmt"
	"vaultaire/core/logs"
)

// GetAllPolicies retourne toutes les GPO pour l'affichage en liste.
func GetAllPolicies(db *sql.DB) ([]PolicySummary, error) {
	rows, err := db.Query(policySelect + ` ORDER BY scope, gpo_name`)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBGeneric, "gpo: liste des GPO échouée : "+err.Error())
		return nil, fmt.Errorf("erreur de lecture des GPO : %v", err)
	}
	defer closeRows(rows)

	var out []PolicySummary
	for rows.Next() {
		p, err := scanPolicyRow(rows)
		if err != nil {
			return nil, fmt.Errorf("erreur de lecture d'une GPO : %v", err)
		}
		out = append(out, PolicySummary{Policy: p})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Comptage des modules et récupération des groupes en dehors de la boucle de
	// scan : lire pendant qu'un *sql.Rows est ouvert monopolise la connexion.
	for i := range out {
		count, err := CountModulesForPolicy(db, out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].ModuleCount = count
		groups, err := GetGroupsForPolicy(db, out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].Groups = groups
	}
	return out, nil
}
