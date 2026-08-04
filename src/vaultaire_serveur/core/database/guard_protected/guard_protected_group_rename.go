package guardprotected

import (
	"strings"
	isprotected "vaultaire/core/database/is_protected"
)

// GuardProtectedGroupRename refuse le renommage du groupe superadmin.
func GuardProtectedGroupRename(currentName, newName string) error {
	if !isprotected.IsProtectedGroup(currentName) {
		return nil
	}
	if strings.TrimSpace(newName) == "" || isprotected.IsProtectedGroup(newName) {
		return nil
	}
	return refuseProtected("groupe", currentName, "le renommage")
}
