package dbgpo

import (
	"database/sql"
	"fmt"
	"strings"
)

// DeleteDefinition supprime une définition à contenu.
//
// Refuse la suppression si la définition est encore référencée par un module de
// GPO : sans ce contrôle, la GPO deviendrait invalide et son application
// échouerait sur le parc, avec une cause difficile à retrouver.
func DeleteDefinition(db *sql.DB, actor string, id int) error {
	if err := requireSuperadmin(db, actor, "la suppression d'une définition"); err != nil {
		return err
	}
	var moduleType, fieldName, name, payload string
	err := db.QueryRow(
		`SELECT module_type, field_name, name, payload FROM gpo_value_definition WHERE id_gpo_value_definition = ?`, id,
	).Scan(&moduleType, &fieldName, &name, &payload)
	if err == sql.ErrNoRows {
		return fmt.Errorf("définition %d introuvable", id)
	}
	if err != nil {
		return fmt.Errorf("lecture de la définition %d impossible : %v", id, err)
	}

	users, err := findModulesUsingValue(db, moduleType, fieldName, name)
	if err != nil {
		return err
	}
	if len(users) > 0 {
		return fmt.Errorf("la définition %q est utilisée par %d module(s) de GPO (%s) : retirez-les d'abord",
			name, len(users), strings.Join(users, ", "))
	}

	if _, err := db.Exec(`DELETE FROM gpo_value_definition WHERE id_gpo_value_definition = ?`, id); err != nil {
		return fmt.Errorf("suppression de la définition %d impossible : %v", id, err)
	}
	auditRestriction(actor, "suppression de définition",
		fmt.Sprintf("%s/%s/%s : %s", moduleType, fieldName, name, oneLine(payload)))
	return nil
}
