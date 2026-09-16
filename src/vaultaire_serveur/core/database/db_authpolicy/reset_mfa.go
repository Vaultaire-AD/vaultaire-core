package dbauthpolicy

import (
	"database/sql"
	"fmt"
	"vaultaire/core/logs"
)

// ResetMFA retire le second facteur d'un compte.
//
// Sert au déblocage — téléphone perdu ou remplacé — et est gardé côté appelant
// par write:mfa. Le secret est effacé et non conservé : un secret désactivé mais
// stocké resterait une clé valide si le drapeau venait à être remis par ailleurs.
func ResetMFA(db *sql.DB, username, resetBy string) error {
	_, err := db.Exec(`UPDATE users
		SET mfa_secret = NULL, mfa_enabled = FALSE, mfa_enrolled_at = NULL, mfa_last_counter = NULL
		WHERE username = ?`, username)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"authpolicy: réinitialisation MFA de "+username+" échouée : "+err.Error())
		return fmt.Errorf("réinitialisation du second facteur : %w", err)
	}

	logs.Write_Log("SECURITY", fmt.Sprintf(
		"authpolicy: second facteur réinitialisé sur %s par %s", username, resetBy))
	return nil
}
