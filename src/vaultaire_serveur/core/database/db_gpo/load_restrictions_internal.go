package dbgpo

import (
	"database/sql"
	"fmt"
	"vaultaire/core/gpo"
	"vaultaire/core/logs"
)

// loadRestrictions construit le jeu de restrictions depuis la base.
func loadRestrictions(db *sql.DB) (gpo.RestrictionSet, error) {
	rs := gpo.RestrictionSet{
		AllowedValues: map[string][]gpo.AllowedValue{},
		Definitions:   map[string][]gpo.ValueDefinition{},
		FieldRules:    map[string]gpo.FieldRule{},
	}

	rows, err := db.Query(
		`SELECT kind, module_type, field_name, scope, value, COALESCE(note, '')
		 FROM gpo_restriction ORDER BY kind, module_type, field_name, value`)
	if err != nil {
		return rs, fmt.Errorf("lecture des restrictions impossible : %v", err)
	}

	for rows.Next() {
		var kind, moduleType, fieldName, scope, value, note string
		if err := rows.Scan(&kind, &moduleType, &fieldName, &scope, &value, &note); err != nil {
			closeRows(rows)
			return rs, err
		}
		switch kind {
		case KindAllowValue:
			key := gpo.FieldKey(moduleType, fieldName)
			rs.AllowedValues[key] = append(rs.AllowedValues[key], gpo.AllowedValue{
				ModuleType: moduleType, FieldName: fieldName, Value: value, Label: note,
			})
		case KindPathAllow:
			rs.PathRules = append(rs.PathRules, gpo.PathRule{Scope: scope, Deny: false, Prefix: value, Note: note})
		case KindPathDeny:
			rs.PathRules = append(rs.PathRules, gpo.PathRule{Scope: scope, Deny: true, Prefix: value, Note: note})
		case KindEnvDeny:
			rs.EnvDenied = append(rs.EnvDenied, gpo.EnvRule{Name: value, Note: note})
		}
	}
	if err := rows.Err(); err != nil {
		closeRows(rows)
		return rs, err
	}
	// Le premier curseur est fermé avant d'ouvrir le second : un *sql.Rows non
	// fermé retient une connexion du pool, et cette fonction est appelée à chaque
	// rechargement du cache de restrictions.
	closeRows(rows)

	ruleRows, err := db.Query(
		`SELECT module_type, field_name, mode, COALESCE(allow_pattern, ''), COALESCE(deny_pattern, ''), COALESCE(note, ''), COALESCE(updated_by, '')
		 FROM gpo_field_rule`)
	if err != nil {
		return rs, fmt.Errorf("lecture des règles de champ impossible : %v", err)
	}
	defer closeRows(ruleRows)

	for ruleRows.Next() {
		var r gpo.FieldRule
		if err := ruleRows.Scan(&r.ModuleType, &r.FieldName, &r.Mode, &r.AllowPattern, &r.DenyPattern, &r.Note, &r.UpdatedBy); err != nil {
			return rs, err
		}
		if !gpo.IsValidFieldMode(r.Mode) {
			logs.Write_Log("WARNING", fmt.Sprintf(
				"gpo: mode de champ inconnu %q pour %s/%s — repli sur le mode liste", r.Mode, r.ModuleType, r.FieldName))
			r.Mode = gpo.FieldModeList
		}
		rs.FieldRules[gpo.FieldKey(r.ModuleType, r.FieldName)] = r
	}
	if err := ruleRows.Err(); err != nil {
		closeRows(ruleRows)
		return rs, err
	}
	closeRows(ruleRows)

	defRows, err := db.Query(
		`SELECT module_type, field_name, name, payload_kind, payload, COALESCE(note, ''), COALESCE(updated_by, '')
		 FROM gpo_value_definition ORDER BY module_type, field_name, name`)
	if err != nil {
		return rs, fmt.Errorf("lecture des définitions impossible : %v", err)
	}
	defer closeRows(defRows)

	for defRows.Next() {
		var d gpo.ValueDefinition
		var kind string
		if err := defRows.Scan(&d.ModuleType, &d.FieldName, &d.Name, &kind, &d.Payload, &d.Note, &d.UpdatedBy); err != nil {
			return rs, err
		}
		d.Kind = gpo.PayloadKind(kind)
		key := gpo.FieldKey(d.ModuleType, d.FieldName)
		rs.Definitions[key] = append(rs.Definitions[key], d)
	}
	return rs, defRows.Err()
}
