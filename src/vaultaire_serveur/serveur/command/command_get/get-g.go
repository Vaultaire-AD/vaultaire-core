package commandget

import (
	"DUCKY/serveur/command/display"
	"DUCKY/serveur/database"
	"DUCKY/serveur/logs"
)

func get_Group_Command_Parser(command_list []string) string {
	if len(command_list) == 3 {
		switch command_list[1] {
		case "-u":
			user_Info, err := database.Command_GET_UsersByGroup(database.GetDatabase(), command_list[2])
			if err != nil {
				logs.Write_Log("WARNING", "error during the get of the user "+command_list[2]+" : "+err.Error())
				return (">> -" + err.Error())
			}
			return display.DisplayUsersByGroup(command_list[2], user_Info)
		case "-c":
			clients_Info, err := database.Command_GET_ClientsByGroup(database.GetDatabase(), command_list[2])
			if err != nil {
				logs.Write_Log("WARNING", "error during the get of the client "+command_list[2]+" : "+err.Error())
				return (">> -" + err.Error())
			}
			return display.DisplayClientsByGroup(clients_Info, command_list[2])
		default:
			return ("Invalid Request Try get -h for more information")
		}
	}
	if command_list[0] == "-g" && len(command_list) == 1 {
		groupDetails, err := database.Command_GET_GroupDetails(database.GetDatabase())
		if err != nil {
			logs.Write_Log("WARNING", "error during the get of all groups : "+err.Error())
			return (">> -" + err.Error())
		}
		return display.DisplayGroupDetails(groupDetails)
	}
	if command_list[0] == "-g" && len(command_list) == 2 {
		groupDetails, err := database.Command_GET_GroupInfo(database.GetDatabase(), command_list[1])
		if err != nil {
			logs.Write_Log("WARNING", "error during the get of the group "+command_list[1]+" : "+err.Error())
			return (">> -" + err.Error())
		}
		return display.DisplayGroupInfo(groupDetails)

	}
	return ("Invalid Request Try get -h for more information")
}
