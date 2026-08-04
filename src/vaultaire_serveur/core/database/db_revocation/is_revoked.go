package dbrevocation

import (
	"database/sql"
	"fmt"
	"vaultaire/core/database"
	"vaultaire/core/logs"
	"vaultaire/core/revocation"
)

// IsRevoked dit si un compte porte un verrouillage soft actif.
//
// LECTURE FAIL-CLOSED : en cas d'erreur de base, la fonction retourne true.
// C'est délibéré et c'est l'inverse du réflexe habituel. Cette fonction garde
// l'authentification : si la base ne répond pas, refuser une connexion
// légitime est un incident d'exploitation, tandis qu'accepter celle d'un compte
// compromis est un incident de sécurité. Le compte d'amorçage `vaultaire` ne
// pouvant pas être révoqué, il reste joignable pour diagnostiquer.
func IsRevoked(db *sql.DB, username string) bool {
	if db == nil {
		logs.Write_Log("ERROR", "revocation: base indisponible, "+username+" traité comme révoqué")
		return true
	}
	if err := database.SanitizeIdentifier(username); err != nil {
		return true
	}

	var count int
	err := db.QueryRow(
		`SELECT COUNT(*) FROM user_revocation
		 WHERE username = ? AND mode = ? AND lifted_at IS NULL`,
		username, string(revocation.ModeSoft)).Scan(&count)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, fmt.Sprintf(
			"revocation: lecture impossible pour %s, compte traité comme révoqué : %v", username, err))
		return true
	}
	return count > 0
}
