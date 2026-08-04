package guardprotected

import isprotected "vaultaire/core/database/is_protected"

// GuardProtectedUserPermissionDeletion refuse la suppression de la permission
// complète du groupe superadmin.
func GuardProtectedUserPermissionDeletion(permissionName string) error {
	if isprotected.IsProtectedUserPermission(permissionName) {
		return refuseProtected("permission", permissionName, "la suppression")
	}
	return nil
}
