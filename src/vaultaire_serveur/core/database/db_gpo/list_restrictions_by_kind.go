package dbgpo

import (
	"database/sql"
	"fmt"
)

// ListRestrictionsByKind retourne les lignes d'une catégorie, pour l'interface.
func ListRestrictionsByKind(db *sql.DB, kind string) ([]RestrictionRow, error) {
	rows, err := db.Query(
		`SELECT id_gpo_restriction, kind, module_type, field_name, scope, value,
		        COALESCE(note, ''), COALESCE(updated_by, ''), updated_at
		 FROM gpo_restriction WHERE kind = ?
		 ORDER BY module_type, field_name, scope, value`, kind)
	if err != nil {
		return nil, fmt.Errorf("lecture des restrictions (%s) impossible : %v", kind, err)
	}
	defer closeRows(rows)

	var out []RestrictionRow
	for rows.Next() {
		var r RestrictionRow
		var updatedAt sql.NullTime
		if err := rows.Scan(&r.ID, &r.Kind, &r.ModuleType, &r.FieldName, &r.Scope, &r.Value, &r.Note, &r.UpdatedBy, &updatedAt); err != nil {
			return nil, err
		}
		if updatedAt.Valid {
			r.UpdatedAt = updatedAt.Time
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
