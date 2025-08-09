package commandget

import (
	"DUCKY/serveur/command/display"
	"DUCKY/serveur/database"
	"DUCKY/serveur/logs"
)

func get_GPO_Command_Parser(command_list []string) string {
	if len(command_list) == 1 {
		gpos, err := database.Command_GET_AllGPO(database.GetDatabase())
		if err != nil {
			logs.Write_Log("WARNING", "error during the get of all GPOs : "+err.Error())
			return (">> -" + err.Error())
		}
		return display.DisplayAllGPOs(gpos)
	}
	if len(command_list) == 2 {
		gpoDetails, err := database.Command_GET_GPOInfoByName(database.GetDatabase(), command_list[1])
		if err != nil {
			logs.Write_Log("WARNING", "error during the get of the GPO "+command_list[1]+" : "+err.Error())
			return (">> -" + err.Error())
		}
		return display.DisplayGPOByName(&gpoDetails)
	}
	return ("Invalid Request Try get -h for more information")
}
