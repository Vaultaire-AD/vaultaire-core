package commandpermission

import (
	"DUCKY/serveur/logs"
	"DUCKY/serveur/permission"
	"fmt"
)

// checkAccess centralise la vérification des permissions sur domaines pour les commandes
func CheckAccess(senderGroupIDs []int, action, senderUsername string, domainList []string) bool {
	ok, resp := permission.CheckPermissionsMultipleDomains(senderGroupIDs, action, domainList)
	if !ok {
		logs.Write_Log("WARNING", fmt.Sprintf("Permission refusée pour %s sur %s : %s", senderUsername, action, resp))
		return false
	}
	return true
}

// logAndReturn log l’erreur et retourne un message formaté
func LogAndReturn(message string, err error) string {
	logs.Write_Log("WARNING", message+err.Error())
	return ">> -" + err.Error()
}

// invalidPermissionRequest retourne un message standardisé
func InvalidPermissionRequest() string {
	return "Invalid Request. Try `get -h` for more information."
}
