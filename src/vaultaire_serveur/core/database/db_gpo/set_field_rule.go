package dbgpo

import (
	"database/sql"
	"fmt"
	"strings"
	"vaultaire/core/gpo"
)

// SetFieldRule définit le mode de validation d'un champ et ses motifs.
//
// Les motifs sont compilés avant écriture : un motif invalide en base bloquerait
// ensuite toute validation du champ, avec un message incompréhensible pour
// l'administrateur suivant.
func SetFieldRule(db *sql.DB, actor, moduleType, fieldName, mode, allowPattern, denyPattern string) error {
	if err := requireSuperadmin(db, actor, "la modification d'une règle de champ"); err != nil {
		return err
	}
	if err := validateFieldTarget(moduleType, fieldName); err != nil {
		return err
	}
	if !gpo.IsValidFieldMode(mode) {
		return fmt.Errorf("mode %q invalide (attendu : %s)", mode, strings.Join(gpo.AllFieldModes(), ", "))
	}
	allowPattern = strings.TrimSpace(allowPattern)
	denyPattern = strings.TrimSpace(denyPattern)
	if err := gpo.ValidatePatternSyntax(allowPattern); err != nil {
		return fmt.Errorf("motif d'autorisation : %v", err)
	}
	if err := gpo.ValidatePatternSyntax(denyPattern); err != nil {
		return fmt.Errorf("motif d'exclusion : %v", err)
	}
	if mode == gpo.FieldModePattern && allowPattern == "" {
		return fmt.Errorf("le mode motif exige un motif d'autorisation")
	}

	previous, _ := GetFieldRule(db, moduleType, fieldName)

	if _, err := db.Exec(
		`INSERT INTO gpo_field_rule (module_type, field_name, mode, allow_pattern, deny_pattern, updated_by)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON DUPLICATE KEY UPDATE mode = VALUES(mode), allow_pattern = VALUES(allow_pattern),
		   deny_pattern = VALUES(deny_pattern), updated_by = VALUES(updated_by)`,
		moduleType, fieldName, mode, nullIfEmpty(allowPattern), nullIfEmpty(denyPattern), actor,
	); err != nil {
		return fmt.Errorf("enregistrement de la règle %s/%s impossible : %v", moduleType, fieldName, err)
	}

	auditRestriction(actor, "modification de règle de champ", fmt.Sprintf(
		"%s/%s : mode %s→%s, allow %q→%q, deny %q→%q",
		moduleType, fieldName, previous.Mode, mode,
		previous.AllowPattern, allowPattern, previous.DenyPattern, denyPattern))
	return nil
}
