package commandupdate

func Update_Command(command_list []string) string {
	switch command_list[0] {
	case "-h", "help", "--help":
		return ("Invalid Request Try get -h for more information")
	case "-pu":
		return update_UserPermission_Command_Parser(command_list)
	default:
		return ("Invalid Request Try get -h for more information")
	}
}
