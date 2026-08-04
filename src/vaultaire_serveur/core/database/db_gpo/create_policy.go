package dbgpo

import (
	"database/sql"
	"fmt"
	"strings"
	"vaultaire/core/database"
	"vaultaire/core/gpo"
	"vaultaire/core/logs"
)

// CreatePolicy crée une GPO vide (sans module ni groupe).
//
// Le nom et le scope sont validés par core/gpo avant écriture : une GPO dont le
// scope serait invalide rendrait la précédence machine/user indécidable.
func CreatePolicy(db *sql.DB, name string, scope gpo.Scope, description string) (int, error) {
	if err := database.SanitizeIdentifier(name); err != nil {
		return 0, err
	}
	if err := gpo.ValidatePolicyName(name); err != nil {
		return 0, err
	}
	if err := gpo.ValidateDescription(description); err != nil {
		return 0, err
	}
	if !gpo.IsValidPolicyScope(scope) {
		return 0, fmt.Errorf("scope invalide %q (attendu : %s ou %s)", scope, gpo.ScopeMachine, gpo.ScopeUser)
	}

	res, err := db.Exec(
		`INSERT INTO gpo (gpo_name, scope, description, version, enabled) VALUES (?, ?, ?, 1, TRUE)`,
		strings.TrimSpace(name), string(scope), strings.TrimSpace(description),
	)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBGeneric, "gpo: création de la GPO "+name+" échouée : "+err.Error())
		return 0, fmt.Errorf("création de la GPO %s impossible : %v", name, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	logs.Write_Log("INFO", fmt.Sprintf("gpo: GPO %s créée (scope %s, id %d)", name, scope, id))
	return int(id), nil
}
