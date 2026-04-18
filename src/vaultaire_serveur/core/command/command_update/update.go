package commandupdate

import (
	"strings"
)

// Update_Command : pour -pu l'action est dans command_list[2] (ex: read:get:user). Pour -debug on utilise write:update:user.
func Update_Command(command_list []string, sender_groupsIDs []int, sender_Username string) string {
	if len(command_list) == 0 {
		return "Invalid Request Try update -h for more information"
	}

	switch command_list[0] {
	case "-h", "help", "--help":
		return (`update -u <username> -p <new_password>
update -pu <PermissionName> <ActionKey> <Arg> [ChildOrAll] [Domain]
update -debug <true|false>`)
	case "-pu":
		// update -pu <perm_name> <action_key> nil|all|-a|-r ... — le sender doit avoir write:update:permission
		return update_UserPermission_Command_Parser(command_list, sender_groupsIDs, "write:update:permission", sender_Username)
	case "-u":
		if len(command_list) >= 3 && strings.EqualFold(command_list[2], "-p") {
			return update_UserPassword_Command_Parser(command_list, sender_groupsIDs, "write:update:user", sender_Username)
		}
		return "Invalid request. Try 'update -h' for more information."

	case "-debug":
		return update_Debug_Command_Parser(command_list, sender_groupsIDs, "write:update:user", sender_Username)
	default:
		return ("Invalid Request Try update -h for more information")
	}
}
