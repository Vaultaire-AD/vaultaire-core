package dbgpo

import (
	"database/sql"
	"fmt"
	"strings"
	"vaultaire/core/database"
)

// AddEnvDeny interdit une variable d'environnement en scope user.
func AddEnvDeny(db *sql.DB, actor, name, note string) error {
	if err := requireSuperadmin(db, actor, "l'interdiction d'une variable d'environnement"); err != nil {
		return err
	}
	name = strings.ToUpper(strings.TrimSpace(name))
	if name == "" {
		return fmt.Errorf("nom de variable requis")
	}
	if err := validateRestrictionValue(name, 64); err != nil {
		return err
	}
	if err := database.SanitizeIdentifier(name); err != nil {
		return err
	}

	res, err := db.Exec(
		`INSERT IGNORE INTO gpo_restriction (kind, scope, value, note, updated_by) VALUES (?, 'any', ?, ?, ?)`,
		KindEnvDeny, name, nullIfEmpty(strings.TrimSpace(note)), actor)
	if err != nil {
		return fmt.Errorf("interdiction de %s impossible : %v", name, err)
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return fmt.Errorf("la variable %s est déjà interdite", name)
	}
	auditRestriction(actor, "interdiction de variable d'environnement", name)
	return nil
}
