package dbgpo

import (
	"database/sql"
	"fmt"
)

// getDefinition lit une définition par sa clé naturelle.
func getDefinition(db *sql.DB, moduleType, fieldName, name string) (DefinitionRow, bool, error) {
	var d DefinitionRow
	err := db.QueryRow(
		`SELECT id_gpo_value_definition, module_type, field_name, name, payload_kind, payload, COALESCE(note, '')
		 FROM gpo_value_definition WHERE module_type = ? AND field_name = ? AND name = ?`,
		moduleType, fieldName, name,
	).Scan(&d.ID, &d.ModuleType, &d.FieldName, &d.Name, &d.PayloadKind, &d.Payload, &d.Note)
	if err == sql.ErrNoRows {
		return d, false, nil
	}
	if err != nil {
		return d, false, fmt.Errorf("lecture de la définition %q impossible : %v", name, err)
	}
	return d, true, nil
}
