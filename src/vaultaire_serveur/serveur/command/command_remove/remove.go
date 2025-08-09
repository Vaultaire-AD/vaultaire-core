package commandremove

import (
	"DUCKY/serveur/command/display"
	"DUCKY/serveur/database"
	"DUCKY/serveur/logs"
)

func Remove_Command(command_list []string) string {
	switch command_list[0] {
	case "-h", "help", "--help":
		return ("LOOK MAN")
	case "-u":
		return remove_User_Command_Parser(command_list)
	case "-c":
		return remove_Client_Command_Parser(command_list)
	case "-g":
		return remove_Group_Command_Parser(command_list)
	case "-gpo":
		return remove_GPO_Command_Parser(command_list)
	default:
		return ("LOOK MAN")
	}
}

func post_displayGroupInfo(groupName string) string {
	groupInfo, err := database.Command_GET_GroupInfo(database.GetDatabase(), groupName)
	if err != nil {
		logs.Write_Log("WARNING", "error during the get of the group "+groupName+" : "+err.Error())
		return (">> -" + err.Error())
	}
	return display.DisplayGroupInfo(groupInfo)
}
