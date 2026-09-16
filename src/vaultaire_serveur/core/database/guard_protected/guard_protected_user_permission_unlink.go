package guardprotected

import isprotected "vaultaire/core/database/is_protected"

// GuardProtectedUserPermissionUnlink refuse de détacher la permission complète
// du groupe superadmin — dernier maillon de la chaîne d'accès administrateur.
func GuardProtectedUserPermissionUnlink(groupName, permissionName string) error {
	if isprotected.IsProtectedGroup(groupName) && isprotected.IsProtectedUserPermission(permissionName) {
		return refuseProtected("permission du groupe superadmin",
			groupName+"/"+permissionName, "le détachement")
	}
	return nil
}
