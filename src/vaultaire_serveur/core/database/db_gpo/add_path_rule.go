package dbgpo

import (
	"database/sql"
	"fmt"
	"strings"
	"vaultaire/core/database"
	"vaultaire/core/gpo"
)

// AddPathRule ajoute une règle de chemin (autorisation ou refus).
func AddPathRule(db *sql.DB, actor, scope string, deny bool, prefix, note string) error {
	operation := "l'ajout d'une autorisation de chemin"
	if deny {
		operation = "l'ajout d'un refus de chemin"
	}
	if err := requireSuperadmin(db, actor, operation); err != nil {
		return err
	}
	if scope != gpo.PathScopeAny && scope != string(gpo.ScopeMachine) && scope != string(gpo.ScopeUser) {
		return fmt.Errorf("scope %q invalide (attendu : any, machine ou user)", scope)
	}
	prefix = strings.TrimSpace(prefix)
	if !strings.HasPrefix(prefix, "/") {
		return fmt.Errorf("un préfixe de chemin doit être absolu : %q", prefix)
	}
	if err := validateRestrictionValue(prefix, 512); err != nil {
		return err
	}
	if err := database.SanitizeInput(prefix); err != nil {
		return err
	}

	kind := KindPathAllow
	if deny {
		kind = KindPathDeny
	}
	res, err := db.Exec(
		`INSERT IGNORE INTO gpo_restriction (kind, scope, value, note, updated_by) VALUES (?, ?, ?, ?, ?)`,
		kind, scope, prefix, nullIfEmpty(strings.TrimSpace(note)), actor)
	if err != nil {
		return fmt.Errorf("ajout de la règle de chemin %q impossible : %v", prefix, err)
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return fmt.Errorf("cette règle existe déjà pour le préfixe %q", prefix)
	}
	auditRestriction(actor, "ajout de règle de chemin",
		fmt.Sprintf("kind=%s scope=%s préfixe=%q", kind, scope, prefix))
	return nil
}
