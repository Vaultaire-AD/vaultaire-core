package dbgpo

import (
	"fmt"
	"vaultaire/core/gpo"
	"vaultaire/core/logs"
)

// auditRestriction journalise une modification de restriction.
func auditRestriction(actor, action, detail string) {
	logs.Write_Log("SECURITY", fmt.Sprintf("gpo/restrictions: %s par %s — %s", action, actor, detail))
	gpo.InvalidateRestrictionCache()
}
