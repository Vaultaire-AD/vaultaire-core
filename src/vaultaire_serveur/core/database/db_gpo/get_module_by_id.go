package dbgpo

import (
	"database/sql"
	"fmt"
	"vaultaire/core/gpo"
)

// GetModuleByID retourne un module et l'identifiant de la GPO qui le porte.
func GetModuleByID(db *sql.DB, moduleID int) (gpo.Module, int, error) {
	var m gpo.Module
	var scope, rawParams string
	var policyID int

	err := db.QueryRow(
		`SELECT id_gpo_module, d_id_gpo, module_type, module_scope, apply_order, params FROM gpo_module WHERE id_gpo_module = ?`,
		moduleID,
	).Scan(&m.ID, &policyID, &m.Type, &scope, &m.ApplyOrder, &rawParams)
	if err == sql.ErrNoRows {
		return m, 0, fmt.Errorf("module %d introuvable", moduleID)
	}
	if err != nil {
		return m, 0, fmt.Errorf("erreur de lecture du module %d : %v", moduleID, err)
	}

	m.PolicyID = policyID
	m.Scope = gpo.Scope(scope)
	if m.Params, err = gpo.DecodeParams(rawParams); err != nil {
		return m, policyID, err
	}
	return m, policyID, nil
}
