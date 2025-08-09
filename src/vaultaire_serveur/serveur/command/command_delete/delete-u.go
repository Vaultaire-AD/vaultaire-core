package commanddelete

import (
	"DUCKY/serveur/database"
	"DUCKY/serveur/logs"
)

// delete_users_Command_Parser handles the deletion of a user by its username.
// It expects a command list with the format: ["-u", "username"].
// If the command is valid, it deletes the user and returns a success message.
// If the command is invalid or an error occurs, it logs the error and returns an error message.
func delete_users_Command_Parser(command_list []string) string {
	if len(command_list) == 2 {
		switch command_list[0] {
		case "-u":
			err := database.Command_DELETE_UserWithUsername(database.GetDatabase(), command_list[1])
			if err != nil {
				logs.Write_Log("WARNING", "error during the deletion of the user "+command_list[1]+" : "+err.Error())
				return (">> -" + err.Error())
			}
			_, err = database.Command_GET_UserInfo(database.GetDatabase(), command_list[1])
			if err != nil {
				return (">> -" + err.Error())
			}
			logs.Write_Log("INFO", "user delete with succes with this ID : "+command_list[1])
			return ("user is delete or never existing")
		default:
			return ("Invalid Request Try get -h for more information : " + command_list[0])
		}
	}
	return ("Invalid Request Try get -h for more information")
}
