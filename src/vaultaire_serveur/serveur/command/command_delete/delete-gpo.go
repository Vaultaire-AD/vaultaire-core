package commanddelete

import (
	"DUCKY/serveur/database"
	"DUCKY/serveur/logs"
)

// delete_GPO_Command_Parser handles the deletion of a GPO by its name.
// It expects a command list with the format: ["-gpo", "gpo_name"].
// If the command is valid, it deletes the GPO and returns a success message.
func delete_GPO_Command_Parser(command_list []string) string {
	if len(command_list) == 2 {
		switch command_list[0] {
		case "-gpo":
			err := database.Command_DELETE_GPOWithGPOName(database.GetDatabase(), command_list[1])
			if err != nil {
				logs.Write_Log("WARNING", "error during the deletion of the GPO "+command_list[1]+" : "+err.Error())
				return (">> -" + err.Error())
			}
			_, err = database.Command_GET_GPOInfoByName(database.GetDatabase(), command_list[1])
			if err != nil {
				return (">> -" + err.Error())
			}
			logs.Write_Log("INFO", "GPO delete with succes with this ID : "+command_list[1])
			return ("GPO is delete or never existing")
		default:
			return ("Invalid Request Try get -h for more information : " + command_list[0])
		}
	}
	return ("Invalid Request Try get -h for more information")
}
