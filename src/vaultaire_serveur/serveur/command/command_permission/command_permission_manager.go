package commandpermission

import (
	"vaultaire/serveur/logs"
	"vaultaire/serveur/permission"
	"fmt"
)

// CheckAccess centralise la vérification des permissions sur domaines pour les commandes get (consult).
// Logs WARNING when permission is refused, INFO when permission is used (consult allowed).
func CheckAccess(senderGroupIDs []int, action, senderUsername string, domainList []string) bool {
	ok, resp := permission.CheckPermissionsMultipleDomains(senderGroupIDs, action, domainList)
	if !ok {
		logs.Write_Log("WARNING", fmt.Sprintf("Permission refused: user=%s action=%s reason=%s", senderUsername, action, resp))
		return false
	}
	logs.Write_Log("INFO", fmt.Sprintf("Permission used: user=%s action=%s (consult)", senderUsername, action))
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
