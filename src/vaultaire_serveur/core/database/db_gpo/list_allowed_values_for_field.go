package dbgpo

import (
	"database/sql"
	"fmt"
)

// ListAllowedValuesForField retourne les valeurs autorisées d'un champ précis.
func ListAllowedValuesForField(db *sql.DB, moduleType, fieldName string) ([]RestrictionRow, error) {
	rows, err := db.Query(
		`SELECT id_gpo_restriction, kind, module_type, field_name, scope, value,
		        COALESCE(note, ''), COALESCE(updated_by, ''), updated_at
		 FROM gpo_restriction WHERE kind = ? AND module_type = ? AND field_name = ?
		 ORDER BY value`, KindAllowValue, moduleType, fieldName)
	if err != nil {
		return nil, fmt.Errorf("lecture des valeurs autorisées de %s/%s impossible : %v", moduleType, fieldName, err)
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
