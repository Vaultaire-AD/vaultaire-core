package dbgpo

import (
	"database/sql"
	"fmt"
	"strings"
	isprotected "vaultaire/core/database/is_protected"
	"vaultaire/core/logs"
)

// requireSuperadmin refuse l'opération si l'acteur n'est pas membre du groupe
// superadmin. Le nom de l'acteur est obligatoire : une écriture anonyme sur les
// restrictions serait intraçable, donc inacceptable.
func requireSuperadmin(db *sql.DB, actor, operation string) error {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return fmt.Errorf("auteur non identifié : opération refusée sur les restrictions GPO")
	}
	if !isprotected.IsSuperadmin(db, actor) {
		logs.Write_Log("SECURITY", fmt.Sprintf(
			"gpo: %s a tenté %s sur les restrictions sans appartenir au groupe %s — refusé",
			actor, operation, isprotected.ProtectedGroupName))
		return fmt.Errorf("réservé aux membres du groupe %s", isprotected.ProtectedGroupName)
	}
	return nil
}
