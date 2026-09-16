package dbgpo

import (
	"database/sql"
	"fmt"
	"vaultaire/core/database"
	"vaultaire/core/logs"
)

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
