package commanddelete

import (
	"DUCKY/serveur/database"
	"DUCKY/serveur/database/db_permission"
	"DUCKY/serveur/logs"
)

// delete_Permission_Command_Parser handles the deletion of permissions.
// It expects a command list with the format: ["-c", "client_permission_name"] or ["-u", "user_permission_name"].
// If the command is valid, it deletes the permission and returns a success message.
// If the command is invalid or an error occurs, it logs the error and returns an error message.
func delete_Permission_Command_Parser(command_list []string) string {
	if len(command_list) == 2 {

		switch command_list[1] {
		case "-c":
			err := db_permission.Command_DELETE_ClientPermissionByName(database.GetDatabase(), command_list[2])
			if err != nil {
				logs.Write_Log("WARNING", "error during the deletion of the client_permission "+command_list[2]+" : "+err.Error())
				return (">> -" + err.Error())
			}
			logs.Write_Log("INFO", "client_permission delete with succes with this ID : "+command_list[2])
			return ("The client_permission :" + command_list[1] + " Has been DELETED With Succes")
		case "-u":
			err := db_permission.Command_DELETE_UserPermissionByName(database.GetDatabase(), command_list[2])
			if err != nil {
				logs.Write_Log("WARNING", "error during the deletion of the user_permission "+command_list[2]+" : "+err.Error())
				return (">> -" + err.Error())
			}
			logs.Write_Log("INFO", "user_permission delete with succes with this ID : "+command_list[2])
			return ("The user_permission :" + command_list[1] + " Has been DELETED With Succes")
		default:
			return ("Invalid Request Try get -h for more information : " + command_list[0])
		}
	}
	return ("Invalid Request Try get -h for more information")
}
