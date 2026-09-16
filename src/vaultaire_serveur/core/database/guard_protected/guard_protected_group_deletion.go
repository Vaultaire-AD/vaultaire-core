package guardprotected

import isprotected "vaultaire/core/database/is_protected"

// GuardProtectedGroupDeletion refuse la suppression du groupe superadmin.
func GuardProtectedGroupDeletion(groupName string) error {
	if isprotected.IsProtectedGroup(groupName) {
		return refuseProtected("groupe", groupName, "la suppression")
	}
	return nil
}
