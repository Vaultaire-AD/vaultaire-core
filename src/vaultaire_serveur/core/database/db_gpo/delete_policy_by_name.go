package dbgpo

import (
	"database/sql"
	"fmt"
	"vaultaire/core/database"
	"vaultaire/core/logs"
)

// DeletePolicyByName supprime une GPO. Les modules et les liaisons de groupe
// partent en cascade via les clés étrangères.
func DeletePolicyByName(db *sql.DB, name string) error {
	if err := database.SanitizeIdentifier(name); err != nil {
		return err
	}
	res, err := db.Exec(`DELETE FROM gpo WHERE gpo_name = ?`, name)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBGeneric, "gpo: suppression de la GPO "+name+" échouée : "+err.Error())
		return fmt.Errorf("suppression de la GPO %s impossible : %v", name, err)
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return fmt.Errorf("GPO %s introuvable", name)
	}
	logs.Write_Log("INFO", "gpo: GPO "+name+" supprimée")
	return nil
}
