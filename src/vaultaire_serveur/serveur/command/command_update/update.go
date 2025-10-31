package commandupdate

func Update_Command(command_list []string, sender_groupsIDs []int, action, sender_Username string) string {
	switch command_list[0] {
	case "-h", "help", "--help":
		return ("Invalid Request Try get -h for more information")
	case "-pu":
		return update_UserPermission_Command_Parser(command_list, sender_groupsIDs, action, sender_Username)
	case "-debug":
		return update_Debug_Command_Parser(command_list, sender_groupsIDs, action, sender_Username)
	default:
		return ("Invalid Request Try get -h for more information")
	}
}
