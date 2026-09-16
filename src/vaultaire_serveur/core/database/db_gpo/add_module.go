package dbgpo

import (
	"database/sql"
	"fmt"
	"vaultaire/core/gpo"
	"vaultaire/core/logs"
)

// AddModule ajoute un module à une GPO.
//
// Le module est validé contre le catalogue et contre le scope de la GPO cible
// AVANT insertion. C'est le point de passage obligé : aucune autre fonction de
// ce package n'écrit dans gpo_module sans validation, ce qui garantit qu'une
// ligne en base correspond toujours à une combinaison autorisée.
func AddModule(db *sql.DB, policyID int, moduleType string, params map[string]string) (int, error) {
	policy, err := GetPolicyByID(db, policyID)
	if err != nil {
		return 0, err
	}

	candidate := gpo.Module{Type: moduleType, Params: params}
	validated, err := gpo.ValidateModule(policy.Scope, candidate)
	if err != nil {
		logs.Write_Log("SECURITY", fmt.Sprintf("gpo: module refusé sur la GPO %s (%s) : %v", policy.Name, moduleType, err))
		return 0, err
	}
	candidate.Params = validated

	// Refus des doublons de clé naturelle : deux modules réglant la même chose
	// dans une même GPO rendraient le résultat dépendant de l'ordre de lecture.
	policy.Modules = append(policy.Modules, candidate)
	if err := gpo.ValidatePolicy(policy); err != nil {
		return 0, err
	}

	schema, _ := gpo.SchemaFor(moduleType)
	encoded, err := gpo.EncodeParams(validated)
	if err != nil {
		return 0, fmt.Errorf("encodage des paramètres impossible : %v", err)
	}

	res, err := db.Exec(
		`INSERT INTO gpo_module (d_id_gpo, module_type, module_scope, apply_order, params) VALUES (?, ?, ?, ?, ?)`,
		policyID, moduleType, string(policy.Scope), schema.ApplyOrder, encoded,
	)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBGeneric, "gpo: insertion du module échouée : "+err.Error())
		return 0, fmt.Errorf("ajout du module %s impossible : %v", moduleType, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}

	if err := BumpVersion(db, policyID); err != nil {
		return int(id), err
	}
	logs.Write_Log("INFO", fmt.Sprintf("gpo: module %s ajouté à la GPO %s le %s (id %d) — %s",
		moduleType, policy.Name, nowStamp(), id, encoded))
	return int(id), nil
}
