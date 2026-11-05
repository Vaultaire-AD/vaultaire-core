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

	// Un compte rendu d'ÉCHEC ne ranime pas une cible levée : la machine
	// répond à un ordre parti avant la levée, et le remettre « en échec » le
	// ferait rejouer — c'est-à-dire refermer un compte rétabli. Un acquittement,
	// lui, s'inscrit toujours : il dit ce qui a été fait.
	garde := ""
	if status == revocation.StatusFailed {
		garde = " AND status <> '" + string(revocation.StatusLifted) + "'"
	}
	_, err := db.Exec(
		`UPDATE user_revocation_target
		    SET status = ?, last_attempt = NOW(), detail = ?
		  WHERE d_id_revocation = ? AND computeur_id = ?`+garde,
		string(status), detail, orderID, computeurID)
	if err != nil {
		return fmt.Errorf("mise à jour de la cible : %w", err)
	}
	return nil
}
