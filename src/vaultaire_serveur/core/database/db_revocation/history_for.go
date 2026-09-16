package dbrevocation

import (
	"database/sql"
	"vaultaire/core/database"
)

// HistoryFor retourne l'historique des ordres visant un compte, du plus récent
// au plus ancien, avec l'avancement de chacun.
func HistoryFor(db *sql.DB, username string) ([]Record, error) {
	if err := database.SanitizeIdentifier(username); err != nil {
		return nil, err
	}
	return queryRecords(db,
		`SELECT r.id_revocation, r.username, r.mode, r.reason_code, r.issued_by, r.issued_at,
		        COALESCE(r.lifted_by, ''), r.lifted_at,
		        COALESCE(SUM(t.status <> 'acked'), 0), COALESCE(COUNT(t.computeur_id), 0)
		   FROM user_revocation r
		   LEFT JOIN user_revocation_target t ON t.d_id_revocation = r.id_revocation
		  WHERE r.username = ?
		  GROUP BY r.id_revocation
		  ORDER BY r.id_revocation DESC`, username)
}
