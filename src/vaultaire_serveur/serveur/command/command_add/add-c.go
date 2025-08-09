package commandadd

import (
	"DUCKY/serveur/command/display"
	"DUCKY/serveur/database"
	"DUCKY/serveur/logs"
)

// add_Client_Command_Parser handles the addition of a software to a client group.
// It expects a command list with the format: ["add", "client_id", "-g", "group_name"].
// If the command is valid, it adds the software to the group and returns the updated software information.
// If the command is invalid or an error occurs, it logs the error and returns an error message.
func add_Client_Command_Parser(command_list []string) string {
	if len(command_list) == 4 {
		switch command_list[2] {
		case "-g":
			err := database.Command_ADD_SoftwareToGroup(database.GetDatabase(), command_list[1], command_list[3])
			if err != nil {
				logs.Write_Log("WARNING", "Error for add group "+command_list[3]+" to software : "+command_list[1]+" : "+err.Error())
				return (">> -" + err.Error())
			}
			user, err := database.Command_GET_ClientByComputeurID(database.GetDatabase(), command_list[1])
			if err != nil {
				logs.Write_Log("WARNING", "Error for get client by id "+command_list[1]+" : "+err.Error())
				return (">> -" + err.Error())
			}
			logs.Write_Log("INFO", "Add group to software : "+command_list[3]+" for client : "+command_list[1])
			return display.DisplaySoftware(user)
		default:
			return ("\nMiss Argument get -h for more information or consult man on the wiki")
		}
	}
	return ("\nMiss Argument get -h for more information or consult man on the wiki")
}
