package dbrevocation

import (
	"database/sql"
	"fmt"
	"vaultaire/core/database"
	"vaultaire/core/logs"
	"vaultaire/core/revocation"
)

// LiftSoftRevocations lève les verrouillages soft actifs d'un compte.
//
// Retourne le nombre de verrous levés, pour distinguer « déverrouillé » de
// « n'était pas verrouillé » — l'interface ne doit pas annoncer une action qui
// n'a rien changé.
func LiftSoftRevocations(db *sql.DB, username, liftedBy string) (int, error) {
	if err := database.SanitizeIdentifier(username, liftedBy); err != nil {
		return 0, err
	}

	res, err := db.Exec(
		`UPDATE user_revocation SET lifted_by = ?, lifted_at = NOW()
		 WHERE username = ? AND mode = ? AND lifted_at IS NULL`,
		liftedBy, username, string(revocation.ModeSoft))
	if err != nil {
		return 0, fmt.Errorf("levée du verrouillage : %w", err)
	}
	affected, _ := res.RowsAffected()
	if affected > 0 {
		logs.Write_Log("SECURITY", fmt.Sprintf(
			"revocation: verrouillage de %s levé par %s (%d ordre(s))", username, liftedBy, affected))
	}
	return int(affected), nil
}
