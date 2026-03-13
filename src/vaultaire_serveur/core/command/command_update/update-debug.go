package commandupdate

import (
	"fmt"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
	"vaultaire/core/storage"
)

func update_Debug_Command_Parser(commandList []string, sender_groupsIDs []int, action, sender_Username string) string {
	if len(commandList) != 2 {
		return "Invalid Request. Try `update -h` for more information."
	}

	// 🔹 Vérification des permissions du sender
	ok, reason := permission.CheckPermissionsMultipleDomains(sender_groupsIDs, action, []string{"*"})
	if !ok {
		logs.Write_Log("WARNING", fmt.Sprintf("Permission refused: user=%s action=%s reason=%s", sender_Username, action, reason))
		return fmt.Sprintf("Permission refusée : %s", reason)
	}
	logs.Write_Log("INFO", fmt.Sprintf("Permission used: user=%s action=%s (update debug)", sender_Username, action))

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
