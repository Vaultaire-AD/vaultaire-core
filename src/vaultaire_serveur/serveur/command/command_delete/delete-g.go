package commanddelete

import (
	"DUCKY/serveur/database"
	"DUCKY/serveur/logs"
)

// delete_Group_Command_Parser handles the deletion of a group by its name.
// It expects a command list with the format: ["-g", "group_name"].
// If the command is valid, it deletes the group and returns a success message.
// If the command is invalid or an error occurs, it logs the error and returns an error message.
func delete_Group_Command_Parser(command_list []string) string {
	if len(command_list) == 2 {
		switch command_list[0] {
		case "-g":
			err := database.Command_DELETE_GroupWithGroupName(database.GetDatabase(), command_list[1])
			if err != nil {
				logs.Write_Log("WARNING", "error during the deletion of the group "+command_list[1]+" : "+err.Error())
				return (">> -" + err.Error())
			}
			_, err = database.Command_GET_GroupInfo(database.GetDatabase(), command_list[1])
			if err != nil {
				return (">> -" + err.Error())
			}
			logs.Write_Log("INFO", "group delete with succes with this ID : "+command_list[1])
			return ("group is delete or never existing")
		default:
			return ("Invalid Request Try get -h for more information : " + command_list[0])
		}
	}
	return ("Invalid Request Try get -h for more information")
}
