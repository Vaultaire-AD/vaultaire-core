package dbrevocation

import (
	"database/sql"
	"fmt"
	"vaultaire/core/logs"
	"vaultaire/core/revocation"
)

// TargetsOf retourne l'état de toutes les machines visées par un ordre.
func TargetsOf(db *sql.DB, orderID int) ([]TargetRecord, error) {
	rows, err := db.Query(
		`SELECT computeur_id, status, last_attempt, COALESCE(detail, '')
		   FROM user_revocation_target
		  WHERE d_id_revocation = ?
		  ORDER BY computeur_id`, orderID)
	if err != nil {
		return nil, fmt.Errorf("lecture des cibles : %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			logs.Write_Log("DEBUG", "revocation: fermeture du curseur: "+cerr.Error())
		}
	}()

	var out []TargetRecord
	for rows.Next() {
		var t TargetRecord
		var status string
		if err := rows.Scan(&t.ComputeurID, &status, &t.LastAttempt, &t.Detail); err != nil {
			return nil, fmt.Errorf("lecture d'une cible : %w", err)
		}
		t.Status = revocation.TargetStatus(status)
		out = append(out, t)
	}
	return out, rows.Err()
}
