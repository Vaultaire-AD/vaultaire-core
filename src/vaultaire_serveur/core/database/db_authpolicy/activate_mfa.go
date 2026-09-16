package dbauthpolicy

import (
	"database/sql"
	"fmt"
	"vaultaire/core/logs"
)

// ActivateMFA active le second facteur après vérification d'un premier code.
//
// `counter` est le pas de temps du code qui vient d'être validé : il est
// consommé du même geste, sinon le code affiché à l'écran resterait rejouable
// pendant sa fenêtre de validité.
func ActivateMFA(db *sql.DB, username string, counter int64) error {
	res, err := db.Exec(`UPDATE users
		SET mfa_enabled = TRUE, mfa_enrolled_at = NOW(), mfa_last_counter = ?
		WHERE username = ? AND mfa_secret IS NOT NULL AND mfa_enabled = FALSE`,
		counter, username)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"authpolicy: activation MFA de "+username+" échouée : "+err.Error())
		return fmt.Errorf("activation du second facteur : %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("aucun enrôlement en cours pour ce compte")
	}

	logs.Write_Log("SECURITY", "authpolicy: second facteur activé sur le compte "+username)
	return nil
}
