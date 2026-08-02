package dbgpo

import (
	"database/sql"
	"fmt"

	"vaultaire/core/database"
	"vaultaire/core/gpo"
	"vaultaire/core/logs"
)

// Liaison GPO ↔ groupes.
//
// Une GPO ne se rattache qu'à des groupes — jamais directement à un utilisateur
// ni à une machine. C'est ce qui permet de garder un seul point de vérité pour
// les droits (le groupe porte déjà les permissions, le domaine et les membres)
// et de rester cohérent avec le modèle de permissions RBAC du projet.
// Une GPO peut être liée à plusieurs groupes, et un groupe porter plusieurs GPO.

// LinkPolicyToGroup rattache une GPO à un groupe.
func LinkPolicyToGroup(db *sql.DB, gpoName, groupName string) error {
	if err := database.SanitizeIdentifier(gpoName, groupName); err != nil {
		return err
	}
	gpoID, err := GetPolicyIDByName(db, gpoName)
	if err != nil {
		return err
	}
	groupID, err := groupIDByName(db, groupName)
	if err != nil {
		return err
	}

	var count int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM gpo_group WHERE d_id_gpo = ? AND d_id_group = ?`, gpoID, groupID,
	).Scan(&count); err != nil {
		return fmt.Errorf("vérification de la liaison GPO-groupe impossible : %v", err)
	}
	if count > 0 {
		return fmt.Errorf("la GPO %s est déjà liée au groupe %s", gpoName, groupName)
	}

	if _, err := db.Exec(`INSERT INTO gpo_group (d_id_gpo, d_id_group) VALUES (?, ?)`, gpoID, groupID); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBGeneric, "gpo: liaison GPO-groupe échouée : "+err.Error())
		return fmt.Errorf("liaison de la GPO %s au groupe %s impossible : %v", gpoName, groupName, err)
	}
	logs.Write_Log("INFO", fmt.Sprintf("gpo: GPO %s liée au groupe %s", gpoName, groupName))
	return nil
}

// UnlinkPolicyFromGroup retire la liaison entre une GPO et un groupe.
func UnlinkPolicyFromGroup(db *sql.DB, gpoName, groupName string) error {
	if err := database.SanitizeIdentifier(gpoName, groupName); err != nil {
		return err
	}
	gpoID, err := GetPolicyIDByName(db, gpoName)
	if err != nil {
		return err
	}
	groupID, err := groupIDByName(db, groupName)
	if err != nil {
		return err
	}

	res, err := db.Exec(`DELETE FROM gpo_group WHERE d_id_gpo = ? AND d_id_group = ?`, gpoID, groupID)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBGeneric, "gpo: retrait de la liaison GPO-groupe échoué : "+err.Error())
		return fmt.Errorf("retrait de la GPO %s du groupe %s impossible : %v", gpoName, groupName, err)
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return fmt.Errorf("la GPO %s n'est pas liée au groupe %s", gpoName, groupName)
	}
	logs.Write_Log("INFO", fmt.Sprintf("gpo: GPO %s retirée du groupe %s", gpoName, groupName))
	return nil
}

// GetGroupsForPolicy retourne les noms des groupes liés à une GPO.
func GetGroupsForPolicy(db *sql.DB, policyID int) ([]string, error) {
	rows, err := db.Query(
		`SELECT g.group_name FROM groups g
		 INNER JOIN gpo_group gg ON gg.d_id_group = g.id_group
		 WHERE gg.d_id_gpo = ? ORDER BY g.group_name`,
		policyID,
	)
	if err != nil {
		return nil, fmt.Errorf("erreur de lecture des groupes de la GPO %d : %v", policyID, err)
	}
	defer closeRows(rows)

	groups := []string{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		groups = append(groups, name)
	}
	return groups, rows.Err()
}

// GetPolicyNamesForGroup retourne les noms des GPO liées à un groupe.
func GetPolicyNamesForGroup(db *sql.DB, groupName string) ([]string, error) {
	if err := database.SanitizeIdentifier(groupName); err != nil {
		return nil, err
	}
	rows, err := db.Query(
		`SELECT gp.gpo_name FROM gpo gp
		 INNER JOIN gpo_group gg ON gg.d_id_gpo = gp.id_gpo
		 INNER JOIN groups g ON g.id_group = gg.d_id_group
		 WHERE g.group_name = ? ORDER BY gp.gpo_name`,
		groupName,
	)
	if err != nil {
		return nil, fmt.Errorf("erreur de lecture des GPO du groupe %s : %v", groupName, err)
	}
	defer closeRows(rows)

	names := []string{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

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

// GetDomainsByGPO retourne les domaines des groupes liés à une GPO.
//
// C'est la clé de la vérification RBAC : les permissions Vaultaire sont
// exprimées par domaine, donc agir sur une GPO exige d'avoir le droit sur tous
// les domaines qu'elle touche. Une GPO non liée à un groupe ne retourne aucun
// domaine — l'appelant doit alors traiter le cas explicitement plutôt que de
// laisser passer une liste vide comme un blanc-seing.
func GetDomainsByGPO(db *sql.DB, gpoName string) ([]string, error) {
	if err := database.SanitizeIdentifier(gpoName); err != nil {
		return nil, err
	}
	rows, err := db.Query(
		`SELECT DISTINCT dg.domain_name FROM gpo gp
		 INNER JOIN gpo_group gg ON gg.d_id_gpo = gp.id_gpo
		 INNER JOIN groups g ON g.id_group = gg.d_id_group
		 INNER JOIN domain_group dg ON dg.d_id_group = g.id_group
		 WHERE gp.gpo_name = ?`,
		gpoName,
	)
	if err != nil {
		logs.Write_Log("ERROR", fmt.Sprintf("gpo: lecture des domaines de la GPO %s échouée : %v", gpoName, err))
		return nil, err
	}
	defer closeRows(rows)

	var domains []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return nil, err
		}
		domains = append(domains, domain)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(domains) == 0 {
		logs.Write_Log("DEBUG", fmt.Sprintf("gpo: aucun domaine trouvé pour la GPO %s", gpoName))
	}
	return domains, nil
}

// groupIDByName résout l'identifiant d'un groupe depuis son nom.
func groupIDByName(db *sql.DB, groupName string) (int, error) {
	var id int
	err := db.QueryRow(`SELECT id_group FROM groups WHERE group_name = ?`, groupName).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, fmt.Errorf("groupe %s introuvable", groupName)
	}
	if err != nil {
		return 0, fmt.Errorf("erreur de lecture du groupe %s : %v", groupName, err)
	}
	return id, nil
}
