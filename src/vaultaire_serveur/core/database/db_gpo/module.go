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

// DeleteModule supprime un module d'une GPO.
func DeleteModule(db *sql.DB, moduleID int) error {
	existing, policyID, err := GetModuleByID(db, moduleID)
	if err != nil {
		return err
	}
	if _, err := db.Exec(`DELETE FROM gpo_module WHERE id_gpo_module = ?`, moduleID); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBGeneric, "gpo: suppression du module échouée : "+err.Error())
		return fmt.Errorf("suppression du module impossible : %v", err)
	}
	if err := BumpVersion(db, policyID); err != nil {
		return err
	}
	logs.Write_Log("INFO", fmt.Sprintf("gpo: module %s (id %d) retiré de la GPO %d le %s",
		existing.Type, moduleID, policyID, nowStamp()))
	return nil
}

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

// CountModulesForPolicy compte les modules d'une GPO.
func CountModulesForPolicy(db *sql.DB, policyID int) (int, error) {
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM gpo_module WHERE d_id_gpo = ?`, policyID).Scan(&count); err != nil {
		return 0, fmt.Errorf("comptage des modules de la GPO %d impossible : %v", policyID, err)
	}
	return count, nil
}

// FindPoliciesUsingModuleType retourne les noms des GPO comportant un module de
// ce type. C'est l'intérêt principal du stockage relationnel : pouvoir répondre
// à « qu'est-ce qui touche à sshd dans le domaine ? » avant de valider un
// changement, plutôt que d'inspecter des blobs JSON.
func FindPoliciesUsingModuleType(db *sql.DB, moduleType string) ([]string, error) {
	if _, ok := gpo.SchemaFor(moduleType); !ok {
		return nil, fmt.Errorf("module inconnu : %s", moduleType)
	}
	rows, err := db.Query(
		`SELECT DISTINCT g.gpo_name FROM gpo g
		 INNER JOIN gpo_module m ON m.d_id_gpo = g.id_gpo
		 WHERE m.module_type = ? ORDER BY g.gpo_name`,
		moduleType,
	)
	if err != nil {
		return nil, fmt.Errorf("recherche par type de module impossible : %v", err)
	}
	defer closeRows(rows)

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}
