package dbgpo

import (
	"database/sql"
	"fmt"
	"vaultaire/core/gpo"
	"vaultaire/core/logs"
)

// GetModulesForPolicy retourne les modules d'une GPO, triés dans l'ordre
// d'application défini par le catalogue (et non par ordre d'insertion).
func GetModulesForPolicy(db *sql.DB, policyID int) ([]gpo.Module, error) {
	rows, err := db.Query(
		`SELECT id_gpo_module, d_id_gpo, module_type, module_scope, apply_order, params
		 FROM gpo_module WHERE d_id_gpo = ? ORDER BY apply_order, id_gpo_module`,
		policyID,
	)
	if err != nil {
		return nil, fmt.Errorf("erreur de lecture des modules de la GPO %d : %v", policyID, err)
	}
	defer closeRows(rows)

	var modules []gpo.Module
	for rows.Next() {
		var m gpo.Module
		var scope, rawParams string
		if err := rows.Scan(&m.ID, &m.PolicyID, &m.Type, &scope, &m.ApplyOrder, &rawParams); err != nil {
			return nil, fmt.Errorf("erreur de lecture d'un module : %v", err)
		}
		m.Scope = gpo.Scope(scope)
		params, err := gpo.DecodeParams(rawParams)
		if err != nil {
			logs.Write_Log("ERROR", fmt.Sprintf("gpo: paramètres illisibles pour le module %d : %v", m.ID, err))
			continue
		}
		m.Params = params
		modules = append(modules, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	gpo.SortModules(modules)
	return modules, nil
}
