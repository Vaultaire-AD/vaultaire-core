package commandupdate

import (
	"DUCKY/serveur/permission"
	"DUCKY/serveur/storage"
	"fmt"
)

func update_Debug_Command_Parser(commandList []string, sender_groupsIDs []int, action, sender_Username string) string {
	if len(commandList) != 2 {
		return "Invalid Request. Try `update -h` for more information."
	}

	// 🔹 Vérification des permissions du sender
	ok, reason := permission.CheckPermissionsMultipleDomains(sender_groupsIDs, action, []string{"*"})
	if !ok {
		return fmt.Sprintf("Permission refusée : %s", reason)
	}

	arg := commandList[1]
	switch arg {
	case "true", "True", "1":
		storage.Debug = true
	case "false", "False", "0":
		storage.Debug = false
	default:
		return "Invalid value. Use `true` or `false`."
	}

	return fmt.Sprintf("Debug mode is now: %v", storage.Debug)
}
