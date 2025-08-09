package commanddelete

import (
	"DUCKY/serveur/database"
	"DUCKY/serveur/logs"
)

// delete_Client_Command_Parser handles the deletion of a client by its computeur ID.
// It expects a command list with the format: ["-c", "computeur_id"].
// If the command is valid, it deletes the client and returns a success message.
// If the command is invalid or an error occurs, it logs the error and returns an error message.
func delete_Client_Command_Parser(command_list []string) string {
	if len(command_list) == 2 {
		if command_list[1] == "vaultaire" {
			return (">> you cannot delete this user")
		}
		switch command_list[0] {
		case "-c":
			err := database.Command_DELETE_ClientWithComputeurID(database.GetDatabase(), command_list[1])
			if err != nil {
				logs.Write_Log("WARNING", "error during the deletion of the client "+command_list[1]+" : "+err.Error())
				return (">> -" + err.Error())
			}
			_, err = database.Command_GET_ClientByComputeurID(database.GetDatabase(), command_list[1])
			if err != nil {
				logs.Write_Log("WARNING", "error during the deletion of the client "+command_list[1]+" : "+err.Error())
				return (">> -" + err.Error())
			}
			logs.Write_Log("INFO", "client delete with succes with this ID : "+command_list[1])
			return ("client is delete or never existing")
		default:
			return ("Invalid Request Try get -h for more information : " + command_list[0])
		}
	}
	return ("Invalid Request Try get -h for more information")
}
