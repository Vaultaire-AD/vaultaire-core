package commandadd

import (
	"DUCKY/serveur/command/display"
	"DUCKY/serveur/database"
	"DUCKY/serveur/logs"
)

// add_User_Command_Parser handles the addition of a user to a group.
// It expects a command list with the format: ["add", "username", "-g", "group_name"].
// If the command is valid, it adds the user to the group and returns the updated user information.
// If the command is invalid or an error occurs, it logs the error and returns an error message.
func add_User_Command_Parser(command_list []string) string {
	if len(command_list) == 4 {
		switch command_list[2] {
		case "-g":
			err := database.Command_ADD_UserToGroup(database.GetDatabase(), command_list[1], command_list[3])
			if err != nil {
				logs.Write_Log("WARNING", "Error for add group "+command_list[3]+" to user : "+command_list[1]+" : "+err.Error())
				return (">> -" + err.Error())
			}
			user, err := database.Command_GET_UserInfo(database.GetDatabase(), command_list[1])
			if err != nil {
				logs.Write_Log("WARNING", "Error for get user by name "+command_list[1]+" : "+err.Error())
				return (">> -" + err.Error())
			}
			logs.Write_Log("INFO", "Add group : "+command_list[3]+" to user : "+command_list[1])
			return display.DisplayUsersInfoByName(user)
		default:
			return ("\nMiss Argument get -h for more information or consult man on the wiki")
		}
	}
	return ("\nMiss Argument get -h for more information or consult man on the wiki")
}
