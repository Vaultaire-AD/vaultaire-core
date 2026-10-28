package gpomanager

import (
	"database/sql"
	"fmt"

	dbgpo "vaultaire/core/database/db_gpo"
	"vaultaire/core/gpo"
	"vaultaire/core/logs"
)

// rangerConflits : remplaçable par les tests.
var rangerConflits = dbgpo.RangerConflits

// noterConflits range les conflits d'une portée (TO-DO 222) et les journalise
// quand ils changent — apparition, changement, disparition. Une erreur de
// base ne retient pas la politique : le reste est livré quoi qu'il arrive.
func noterConflits(db *sql.DB, clientID string, scope gpo.Scope, targetUser string, conflits []gpo.Conflict) {
	detail := gpo.DecrireConflits(conflits)
	change, err := rangerConflits(db, clientID, string(scope), targetUser, detail)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeGPOResolve, "gpo: "+err.Error())
	}
	if !change && err == nil {
		return
	}
	cible := clientID
	if targetUser != "" {
		cible = targetUser + " sur " + clientID
	}
	if detail == "" {
		logs.Write_LogCode("INFO", logs.CodeGPOResolve, fmt.Sprintf(
			"gpo: plus de conflit entre GPO (%s, %s)", cible, scope))
		return
	}
	logs.Write_LogCode("WARNING", logs.CodeGPOResolve, fmt.Sprintf(
		"gpo: conflit entre GPO (%s, %s) — modules écartés, le reste est livré : %s", cible, scope, detail))
}
