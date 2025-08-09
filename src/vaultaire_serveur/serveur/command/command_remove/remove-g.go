package commandremove

import (
	"DUCKY/serveur/command/display"
	"DUCKY/serveur/database"
	"DUCKY/serveur/logs"
)

func remove_Group_Command_Parser(command_list []string) string {
	if len(command_list) == 4 {
		switch command_list[2] {
		case "-pc":
			err := database.Command_Remove_ClientPermissionFromGroup(database.GetDatabase(), command_list[1], command_list[3])
			if err != nil {
				logs.Write_Log("WARNING", "error during the removal of the client "+command_list[1]+" From "+command_list[3]+" : "+err.Error())
				return (">> -" + err.Error())
			}
			client_Info, err := database.Command_GET_GroupInfo(database.GetDatabase(), command_list[1])
			if err != nil {
				logs.Write_Log("WARNING", "error during the get of the group "+command_list[1]+" : "+err.Error())
				return (">> -" + err.Error())
			}
			logs.Write_Log("INFO", "Client "+command_list[1]+" removed from permission "+command_list[3])
			return display.DisplayGroupInfo(client_Info)
		case "-pu":
			err := database.Command_Remove_UserPermissionFromGroup(database.GetDatabase(), command_list[1], command_list[3])
			if err != nil {
				logs.Write_Log("WARNING", "error during the removal of the user "+command_list[1]+" From "+command_list[3]+" : "+err.Error())
				return (">> -" + err.Error())
			}
			client_Info, err := database.Command_GET_GroupInfo(database.GetDatabase(), command_list[1])
			if err != nil {
				logs.Write_Log("WARNING", "error during the get of the group "+command_list[1]+" : "+err.Error())
				return (">> -" + err.Error())
			}
			logs.Write_Log("INFO", "User "+command_list[1]+" removed from permission "+command_list[3])
			return display.DisplayGroupInfo(client_Info)
		default:
			return ("\nMiss Argument status -h for more information or consult man on the wiki")
		}
	}
	return ("\nMiss Argument status -h for more information or consult man on the wiki")
}
