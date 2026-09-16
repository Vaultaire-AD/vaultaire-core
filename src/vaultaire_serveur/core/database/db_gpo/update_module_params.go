package dbgpo

import (
	"database/sql"
	"fmt"
	"vaultaire/core/gpo"
	"vaultaire/core/logs"
)

// UpdateModuleParams remplace les paramètres d'un module existant.
//
// Le module conserve son type : changer le type reviendrait à supprimer puis
// recréer, avec des champs qui n'auraient plus de sens.
func UpdateModuleParams(db *sql.DB, moduleID int, params map[string]string) error {
	existing, policyID, err := GetModuleByID(db, moduleID)
	if err != nil {
		return err
	}
	policy, err := GetPolicyByID(db, policyID)
	if err != nil {
		return err
	}

	candidate := gpo.Module{ID: moduleID, Type: existing.Type, Params: params}
	validated, err := gpo.ValidateModule(policy.Scope, candidate)
	if err != nil {
		logs.Write_Log("SECURITY", fmt.Sprintf("gpo: mise à jour de module refusée sur la GPO %s (%s) : %v", policy.Name, existing.Type, err))
		return err
	}
	candidate.Params = validated

	// Revalidation de la GPO entière avec le module remplacé, pour rattraper un
	// doublon créé par la modification (ex. deux modules pointant le même service).
	rebuilt := *policy
	rebuilt.Modules = nil
	for _, m := range policy.Modules {
		if m.ID == moduleID {
			rebuilt.Modules = append(rebuilt.Modules, candidate)
			continue
		}
		rebuilt.Modules = append(rebuilt.Modules, m)
	}
	if err := gpo.ValidatePolicy(&rebuilt); err != nil {
		return err
	}

	encoded, err := gpo.EncodeParams(validated)
	if err != nil {
		return fmt.Errorf("encodage des paramètres impossible : %v", err)
	}
	if _, err := db.Exec(`UPDATE gpo_module SET params = ? WHERE id_gpo_module = ?`, encoded, moduleID); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBGeneric, "gpo: mise à jour du module échouée : "+err.Error())
		return fmt.Errorf("mise à jour du module impossible : %v", err)
	}
	if err := BumpVersion(db, policyID); err != nil {
		return err
	}
	logs.Write_Log("INFO", fmt.Sprintf("gpo: module %s (id %d) de la GPO %s mis à jour le %s — %s",
		existing.Type, moduleID, policy.Name, nowStamp(), encoded))
	return nil
}
