package commandupdate

import (
	"DUCKY/serveur/storage"
	"fmt"
)

func update_Debug_Command_Parser(commandList []string) string {
	if len(commandList) != 2 {
		return "Invalid Request. Try `get -h` for more information."
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
