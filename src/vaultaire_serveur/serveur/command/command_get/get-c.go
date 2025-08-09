package commandget

import (
	"DUCKY/serveur/command/display"
	"DUCKY/serveur/database"
	"DUCKY/serveur/logs"
)

func get_Client_Command_Parser(command_list []string) string {
	if len(command_list) == 1 {
		allClient, err := database.Command_GET_AllClients(database.GetDatabase())
		if err != nil {
			logs.Write_Log("WARNING", "error during the get of all clients : "+err.Error())
			return (">> -" + err.Error())
		}
		return display.DisplayAllClients(allClient)
	}
	if len(command_list) == 2 {
		client, err := database.Command_GET_ClientByComputeurID(database.DB, command_list[1])
		if err != nil {
			logs.Write_Log("WARNING", "error during the get of the client "+command_list[1]+" : "+err.Error())
			return (">> -" + err.Error())
		}
		return display.DisplaySoftware(client)
	}
	return ("Invalid Request Try get -h for more information")
}
