package guardprotected

import isprotected "vaultaire/core/database/is_protected"

// GuardProtectedClientPermissionDeletion refuse la suppression de la permission
// client d'administration.
func GuardProtectedClientPermissionDeletion(permissionName string) error {
	if isprotected.IsProtectedClientPermission(permissionName) {
		return refuseProtected("permission client", permissionName, "la suppression")
	}
	return nil
}
