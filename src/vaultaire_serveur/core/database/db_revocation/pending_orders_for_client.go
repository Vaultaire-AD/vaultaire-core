package dbrevocation

import (
	"database/sql"
	"fmt"
	"vaultaire/core/database"
	"vaultaire/core/logs"
	"vaultaire/core/revocation"
)

// PendingOrdersForClient retourne les ordres qu'une machine n'a pas encore
// acquittés, du plus ancien au plus récent.
//
// L'ordre chronologique compte : un verrouillage suivi d'un déverrouillage doit
// être rejoué dans cet ordre, sinon la machine terminerait verrouillée alors
// que le compte a été rétabli.
func PendingOrdersForClient(db *sql.DB, computeurID string, limit int) ([]revocation.Order, error) {
	if err := database.SanitizeIdentifier(computeurID); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 200 {
		limit = 200
	}

	rows, err := db.Query(
		`SELECT r.id_revocation, r.mode, r.username, r.reason_code
		   FROM user_revocation r
		   JOIN user_revocation_target t ON t.d_id_revocation = r.id_revocation
		  WHERE t.computeur_id = ? AND t.status <> ?
		  ORDER BY r.id_revocation ASC
		  LIMIT ?`,
		computeurID, string(revocation.StatusAcked), limit)
	if err != nil {
		return nil, fmt.Errorf("lecture des ordres en attente : %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			logs.Write_Log("DEBUG", "revocation: fermeture du curseur: "+cerr.Error())
		}
	}()

	var orders []revocation.Order
	for rows.Next() {
		var o revocation.Order
		var mode, reason string
		if err := rows.Scan(&o.ID, &mode, &o.Username, &reason); err != nil {
			return nil, fmt.Errorf("lecture d'un ordre : %w", err)
		}
		o.Mode = revocation.Mode(mode)
		o.Reason = revocation.Reason(reason)
		if err := o.Validate(); err != nil {
			// Une ligne corrompue n'interrompt pas les autres : mieux vaut
			// appliquer les ordres lisibles que de tout bloquer.
			logs.Write_LogCode("WARNING", logs.CodeDBQuery,
				"revocation: ordre illisible ignoré: "+err.Error())
			continue
		}
		orders = append(orders, o)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("parcours des ordres : %w", err)
	}
	return orders, nil
}
