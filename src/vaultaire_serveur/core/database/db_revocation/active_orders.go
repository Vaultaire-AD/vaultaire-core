package dbrevocation

import (
	"database/sql"
)

// ActiveOrders retourne tous les verrouillages soft en vigueur, pour la vue
// d'ensemble de l'interface.
func ActiveOrders(db *sql.DB) ([]Record, error) {
	return queryRecords(db,
		`SELECT r.id_revocation, r.username, r.mode, r.reason_code, r.issued_by, r.issued_at,
		        COALESCE(r.lifted_by, ''), r.lifted_at,
		        COALESCE(SUM(t.status <> 'acked'), 0), COALESCE(COUNT(t.computeur_id), 0)
		   FROM user_revocation r
		   LEFT JOIN user_revocation_target t ON t.d_id_revocation = r.id_revocation
		  WHERE r.lifted_at IS NULL
		  GROUP BY r.id_revocation
		  ORDER BY r.issued_at DESC`)
}
