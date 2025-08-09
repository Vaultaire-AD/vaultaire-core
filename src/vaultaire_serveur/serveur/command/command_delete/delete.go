package commanddelete

// Management pour les commandes delete
func Delete_Command(command_list []string) string {
	switch command_list[0] {
	case "-h", "help", "--help":
		return (`delete -u "username"
delete -p "permission_name"
delete -g "group_name"
delete -c "computeur_id"`)
	case "-u":
		return delete_users_Command_Parser(command_list)
	case "-c":
		return delete_Client_Command_Parser(command_list)
	case "-p":
		return delete_Permission_Command_Parser(command_list)
	case "-g":
		return delete_Group_Command_Parser(command_list)
	case "-gpo":
		return delete_GPO_Command_Parser(command_list)
	default:
		return ("Invalid Request Try get -h for more information : " + command_list[0])
	}
}
