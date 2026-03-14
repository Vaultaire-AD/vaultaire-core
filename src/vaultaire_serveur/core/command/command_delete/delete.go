package commanddelete

// Delete_Command : clé RBAC write:delete:user, write:delete:group, write:delete:client selon sous-commande.
func Delete_Command(command_list []string, sender_groupsIDs []int, sender_Username string) string {
	actionKey := "write:delete:group"
	switch command_list[0] {
	case "-h", "help", "--help":
		return (`delete -u "username"
delete -p "permission_name"
delete -g "group_name"
delete -c "computeur_id"`)
	case "-u":
		actionKey = "write:delete:user"
	case "-c":
		actionKey = "write:delete:client"
	case "-p":
		actionKey = "write:delete:permission"
	case "-g":
		actionKey = "write:delete:group"
	case "-gpo":
		actionKey = "write:delete:gpo"
	}
	switch command_list[0] {
	case "-u":
		return delete_users_Command_Parser(command_list, sender_groupsIDs, actionKey, sender_Username)
	case "-c":
		return delete_Client_Command_Parser(command_list, sender_groupsIDs, actionKey, sender_Username)
	case "-p":
		return delete_Permission_Command_Parser(command_list, sender_groupsIDs, actionKey, sender_Username)
	case "-g":
		return delete_Group_Command_Parser(command_list, sender_groupsIDs, actionKey, sender_Username)
	case "-gpo":
		return delete_GPO_Command_Parser(command_list, sender_groupsIDs, actionKey, sender_Username)
	default:
		return ("Invalid Request Try get -h for more information : " + command_list[0])
	}
}
