package dbauthpolicy

import (
	"database/sql"
	"fmt"
	"vaultaire/core/logs"
)

// SetGroupMFARequired pose ou retire l'exigence de second facteur sur un groupe.
func SetGroupMFARequired(db *sql.DB, groupName string, required bool, updatedBy string) error {
	res, err := db.Exec(`UPDATE groups SET mfa_required = ? WHERE group_name = ?`, required, groupName)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"authpolicy: mise à jour de mfa_required sur "+groupName+" échouée : "+err.Error())
		return fmt.Errorf("mise à jour du groupe %s : %w", groupName, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// Zéro ligne peut signifier « groupe inconnu » ou « valeur déjà posée ».
		// On vérifie plutôt que d'annoncer un succès sur un nom mal orthographié.
		var exists int
		if err := db.QueryRow(`SELECT COUNT(*) FROM groups WHERE group_name = ?`, groupName).Scan(&exists); err == nil && exists == 0 {
			return fmt.Errorf("groupe %s inconnu", groupName)
		}
	}

	state := "retirée de"
	if required {
		state = "posée sur"
	}
	logs.Write_Log("SECURITY", fmt.Sprintf(
		"authpolicy: exigence MFA %s le groupe %s par %s", state, groupName, updatedBy))
	return nil
}
