package dbgpo

import (
	"database/sql"
	"fmt"
	"vaultaire/core/logs"
)

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
