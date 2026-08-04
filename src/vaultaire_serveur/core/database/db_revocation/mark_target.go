package dbrevocation

import (
	"database/sql"
	"fmt"
	"vaultaire/core/database"
	"vaultaire/core/revocation"
)

// MarkTarget enregistre le compte rendu d'une machine pour un ordre.
func MarkTarget(db *sql.DB, orderID int, computeurID string, status revocation.TargetStatus, detail string) error {
	if err := database.SanitizeIdentifier(computeurID); err != nil {
		return err
	}
	// Le détail vient de l'agent : borné pour ne pas laisser une machine écrire
	// un volume arbitraire dans la base du serveur.
	if len(detail) > 512 {
		detail = detail[:512]
	}

	_, err := db.Exec(
		`UPDATE user_revocation_target
		    SET status = ?, last_attempt = NOW(), detail = ?
		  WHERE d_id_revocation = ? AND computeur_id = ?`,
		string(status), detail, orderID, computeurID)
	if err != nil {
		return fmt.Errorf("mise à jour de la cible : %w", err)
	}
	return nil
}
