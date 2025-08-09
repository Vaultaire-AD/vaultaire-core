package commandstatus

import (
	"DUCKY/serveur/command/display"
	"DUCKY/serveur/database"
	"DUCKY/serveur/logs"
)

func status_Client_Command_Parser(command_list []string) string {
	if command_list[0] == "-c" && len(command_list) == 1 {
		client_Login, err := database.Command_STATUS_GetClientsConnected(database.GetDatabase())
		if err != nil {
			logs.Write_Log("WARNING", "error during the get of all clients : "+err.Error())
			return (">> -" + err.Error())
		}
		return display.DisplayClientsByStatus(client_Login)
	} else if len(command_list) == 3 {
		switch command_list[1] {
		case "-g":
			client_Login, err := database.Command_STATUS_GetClientsConnectedByGroup(database.GetDatabase(), command_list[2])
			if err != nil {
				logs.Write_Log("WARNING", "error during the get of the client "+command_list[2]+" : "+err.Error())
				return (">> -" + err.Error())
			}
			return display.DisplayClientsByStatus(client_Login)
		default:
			Client_Login, _ := database.Command_STATUS_GetClientsConnected(database.GetDatabase())
			return display.DisplayClientsByStatus(Client_Login)
		}
	}
	if len(command_list) == 2 {
		Client_Login, err := database.Command_STATUS_GetClientsConnectedByLogicielType(database.GetDatabase(), command_list[1])
		if err != nil {
			logs.Write_Log("WARNING", "error during the get of the client "+command_list[1]+" : "+err.Error())
			return (">> -" + err.Error())
		}
		return display.DisplayClientsByStatus(Client_Login)
	} else {
		return ("\nMiss Argument status -h for more information or consult man on the wiki")
	}
}
