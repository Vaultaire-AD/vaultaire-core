package commandadd

import (
	"DUCKY/serveur/database"
	"DUCKY/serveur/database/db_permission"
	"DUCKY/serveur/logs"
)

// add_group_Command_Parser handles the addition of a user permission or client permission to a group.
// It expects a command list with the format: ["add", "-gu/-gc", "group_name", "permission_name"].
// If the command is valid, it adds the permission to the group and returns the updated group information.
// If the command is invalid or an error occurs, it logs the error and returns an empty string.
func add_group_Command_Parser(command_list []string) string {
	if len(command_list) == 4 {
		switch command_list[0] {
		case "-gu":
			err := db_permission.Command_ADD_UserPermissionToGroup(database.GetDatabase(), command_list[3], command_list[1])
			if err != nil {
				logs.Write_Log("WARNING", "Error for add user_permission "+command_list[3]+" to group "+command_list[1]+" : "+err.Error())
				return (">> -" + err.Error())
			}
			logs.Write_Log("INFO", "Add user_permission to group : "+command_list[1]+" for user : "+command_list[3])
			return post_displayGroupInfo(command_list[1])
		case "-gc":
			err := database.Command_ADD_PermissionToSoftwareGroup(database.GetDatabase(), command_list[3], command_list[1])
			if err != nil {
				logs.Write_Log("WARNING", "Error for add client_permission "+command_list[3]+" to group "+command_list[1]+" : "+err.Error())
				return (">> -" + err.Error())
			}
			logs.Write_Log("INFO", "Add client_permission to group : "+command_list[1]+" for client : "+command_list[3])
			return post_displayGroupInfo(command_list[1])
		default:
			return ("\nMiss Argument get -h for more information or consult man on the wiki")
		}
	}
	return ("\nMiss Argument get -h for more information or consult man on the wiki")
}
