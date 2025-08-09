package commandstatus

import (
	"DUCKY/serveur/command/display"
	"DUCKY/serveur/database"
	"DUCKY/serveur/logs"
)

func status_User_Command_Parser(command_list []string) string {
	if len(command_list) == 2 {
		users_Login, _ := database.Command_STATUS_GetConnectedUser(database.GetDatabase(), command_list[1])
		return display.DisplayUsersByStatus(users_Login)
	} else if len(command_list) == 3 {
		switch command_list[1] {
		case "-g":
			users_Login, err := database.Command_STATUS_GetUsersByGroup(database.GetDatabase(), command_list[2])
			if err != nil {
				logs.Write_Log("WARNING", "error during the get of the user "+command_list[2]+" : "+err.Error())
				return (">> -" + err.Error())
			}
			return display.DisplayUsersByStatus(users_Login)
		default:
			Users_Login, _ := database.Command_STATUS_GetConnectedUsers(database.GetDatabase())
			return display.DisplayUsersByStatus(Users_Login)
		}
	}
	if command_list[0] == "-u" && len(command_list) == 1 {
		Users_Login, _ := database.Command_STATUS_GetConnectedUsers(database.GetDatabase())
		return display.DisplayUsersByStatus(Users_Login)
	} else {
		return ("\nMiss Argument status -h for more information or consult man on the wiki")
	}
}
