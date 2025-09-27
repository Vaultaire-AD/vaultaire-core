package commandupdate

func update_UserPermission_Command_Parser(command_list []string) string {
	// if len(command_list) == 4 {
	// 	newValue := tools.String_tobool_yesnot(command_list[3])
	// 	err := database.UpdateUserPermissionBooleanField(database.GetDatabase(), command_list[1], command_list[2], newValue)
	// 	if err != nil {
	// 		return ">> -" + err.Error()
	// 	}
	// 	permission, err := database.Command_GET_UserPermissionByName(database.GetDatabase(), command_list[1])
	// 	if err != nil {
	// 		return ">> -" + err.Error()
	// 	}
	// 	return display.DisplayUserPermission(*permission)

	// }
	return ("Invalid Request Try update -h for more information")
}
