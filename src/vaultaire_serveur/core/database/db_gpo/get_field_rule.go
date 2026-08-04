package dbgpo

import (
	"database/sql"
	"fmt"
	"vaultaire/core/gpo"
)

// GetFieldRule retourne la règle enregistrée pour un champ.
func GetFieldRule(db *sql.DB, moduleType, fieldName string) (FieldRuleRow, error) {
	var r FieldRuleRow
	var updatedAt sql.NullTime
	err := db.QueryRow(
		`SELECT id_gpo_field_rule, module_type, field_name, mode,
		        COALESCE(allow_pattern, ''), COALESCE(deny_pattern, ''), COALESCE(note, ''), COALESCE(updated_by, ''), updated_at
		 FROM gpo_field_rule WHERE module_type = ? AND field_name = ?`, moduleType, fieldName,
	).Scan(&r.ID, &r.ModuleType, &r.FieldName, &r.Mode, &r.AllowPattern, &r.DenyPattern, &r.Note, &r.UpdatedBy, &updatedAt)
	if err == sql.ErrNoRows {
		return FieldRuleRow{ModuleType: moduleType, FieldName: fieldName, Mode: gpo.FieldModeList}, nil
	}
	if err != nil {
		return r, fmt.Errorf("lecture de la règle %s/%s impossible : %v", moduleType, fieldName, err)
	}
	if updatedAt.Valid {
		r.UpdatedAt = updatedAt.Time
	}
	return r, nil
}
