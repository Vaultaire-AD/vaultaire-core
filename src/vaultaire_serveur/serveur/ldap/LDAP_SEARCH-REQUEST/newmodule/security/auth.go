package security

import (
	"DUCKY/serveur/database"
	"DUCKY/serveur/database/db_permission"
	"DUCKY/serveur/permission"
)

func IsAuthorizedToSearch(username, baseDN string) bool {
	perms, err := db_permission.GetUserPermissionsForAction(
		database.GetDatabase(),
		username,
		"search",
	)
	if err != nil {
		return false
	}
	return permission.IsUserAuthorizedToSearch(perms, baseDN)
}
