package commandget

import (
	"DUCKY/serveur/command/display"
	"DUCKY/serveur/database"
	"DUCKY/serveur/logs"
)

func get_User_Command_Parser(command_list []string) string {
	if len(command_list) == 1 {
		users, err := database.Command_GET_AllUsers(database.GetDatabase())
		if err != nil {
			logs.Write_Log("WARNING", "error during the get of all users : "+err.Error())
			return (">> -" + err.Error())
		}
		return display.DisplayAllUsers(users)

	}
	if len(command_list) == 2 {
		user_Info, err := database.Command_GET_UserInfo(database.GetDatabase(), command_list[1])
		if err != nil {
			logs.Write_Log("WARNING", "error during the get of the user "+command_list[1]+" : "+err.Error())
			return (">> -" + err.Error())
		}
		return display.DisplayUsersInfoByName(user_Info)
	} else if len(command_list) == 3 {
		switch command_list[1] {
		case "-g":
			user_Info, err := database.Command_GET_UsersByGroup(database.GetDatabase(), command_list[2])
			if err != nil {
				logs.Write_Log("WARNING", "error during the get of the user "+command_list[2]+" : "+err.Error())
				return (">> -" + err.Error())
			}
			return display.DisplayUsersByGroup(command_list[2], user_Info)
		default:
			return ("\nMiss Argument get -h for more information or consult man on the wiki")
		}
	}
	return ("\nMiss Argument get -h for more information or consult man on the wiki")
}
