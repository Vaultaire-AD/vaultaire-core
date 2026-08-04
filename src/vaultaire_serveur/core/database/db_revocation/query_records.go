package dbrevocation

import (
	"database/sql"
	"fmt"
	"vaultaire/core/logs"
	"vaultaire/core/revocation"
)

// queryRecords factorise la lecture d'ordres, les deux requêtes ci-dessus ne
// différant que par leur clause WHERE.
func queryRecords(db *sql.DB, query string, args ...interface{}) ([]Record, error) {
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("lecture des révocations : %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			logs.Write_Log("DEBUG", "revocation: fermeture du curseur: "+cerr.Error())
		}
	}()

	var out []Record
	for rows.Next() {
		var r Record
		var mode, reason string
		if err := rows.Scan(&r.ID, &r.Username, &mode, &reason, &r.IssuedBy, &r.IssuedAt,
			&r.LiftedBy, &r.LiftedAt, &r.Pending, &r.Total); err != nil {
			return nil, fmt.Errorf("lecture d'une révocation : %w", err)
		}
		r.Mode = revocation.Mode(mode)
		r.Reason = revocation.Reason(reason)
		out = append(out, r)
	}
	return out, rows.Err()
}
