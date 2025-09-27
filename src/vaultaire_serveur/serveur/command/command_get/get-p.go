package commandget

import (
	"DUCKY/serveur/command/display"
	"DUCKY/serveur/database"
	"DUCKY/serveur/database/db_permission"
	"DUCKY/serveur/logs"
)

func get_Permission_Command_Parser(command_list []string) string {
	if len(command_list) == 2 {
		switch command_list[1] {
		case "-u":
			permission, err := db_permission.Command_GET_AllUserPermissions(database.GetDatabase())
			if err != nil {
				logs.Write_Log("WARNING", "error during the get of all permissions : "+err.Error())
				return (">> -" + err.Error())
			}
			return display.DisplayAllUserPermissions(permission)
		case "-c":
			permission, err := database.Command_GET_AllClientPermissions(database.GetDatabase())
			if err != nil {
				logs.Write_Log("WARNING", "error during the get of all permissions : "+err.Error())
				return (">> -" + err.Error())
			}
			return display.DisplayAllClientPermissions(permission)
		}

	}
	if len(command_list) == 3 {
		switch command_list[1] {
		case "-c":
			permission, err := database.Command_GET_ClientPermissionByName(database.GetDatabase(), command_list[2])
			if err != nil {
				logs.Write_Log("WARNING", "error during the get of all permissions : "+err.Error())
				return (">> -" + err.Error())
			}
			return display.DisplayClientPermission(*permission)
		case "-u":
			permission, err := db_permission.Command_GET_UserPermissionByName(database.GetDatabase(), command_list[2])
			if err != nil {
				logs.Write_Log("WARNING", "error during the get of all permissions : "+err.Error())
				return (">> -" + err.Error())
			}
			return display.DisplayUserPermission(*permission)
		default:
			return ("Invalid Request Try get -h for more information")
		}
	}

	return ("Invalid Request Try get -h for more information")
}
