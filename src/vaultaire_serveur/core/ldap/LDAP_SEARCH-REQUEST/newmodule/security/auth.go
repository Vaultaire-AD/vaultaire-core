package security

import (
	"vaultaire/core/database"
	dbpermission "vaultaire/core/database/db_permission"
	"vaultaire/core/permission"
)

func IsAuthorizedToSearch(username, baseDN string) bool {
	perms, err := dbpermission.GetUserPermissionsForAction(
		database.GetDatabase(),
		username,
		"search",
	)
	if err != nil {
		return false
	}
	return permission.IsUserAuthorizedToSearch(perms, baseDN)
}
