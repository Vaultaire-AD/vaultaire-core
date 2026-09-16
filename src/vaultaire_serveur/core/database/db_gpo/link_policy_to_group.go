package dbgpo

import (
	"database/sql"
	"fmt"
	"vaultaire/core/database"
	"vaultaire/core/logs"
)

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
