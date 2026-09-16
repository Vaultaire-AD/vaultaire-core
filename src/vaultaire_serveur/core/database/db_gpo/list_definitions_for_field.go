package dbgpo

import (
	"database/sql"
	"fmt"
)

// ListDefinitionsForField retourne les définitions d'un champ, pour l'interface.
func ListDefinitionsForField(db *sql.DB, moduleType, fieldName string) ([]DefinitionRow, error) {
	rows, err := db.Query(
		`SELECT id_gpo_value_definition, module_type, field_name, name, payload_kind, payload,
		        COALESCE(note, ''), COALESCE(updated_by, ''), updated_at
		 FROM gpo_value_definition WHERE module_type = ? AND field_name = ? ORDER BY name`,
		moduleType, fieldName)
	if err != nil {
		return nil, fmt.Errorf("lecture des définitions de %s/%s impossible : %v", moduleType, fieldName, err)
	}
	defer closeRows(rows)

	var out []DefinitionRow
	for rows.Next() {
		var d DefinitionRow
		var updatedAt sql.NullTime
		if err := rows.Scan(&d.ID, &d.ModuleType, &d.FieldName, &d.Name, &d.PayloadKind,
			&d.Payload, &d.Note, &d.UpdatedBy, &updatedAt); err != nil {
			return nil, err
		}
		if updatedAt.Valid {
			d.UpdatedAt = updatedAt.Time
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
