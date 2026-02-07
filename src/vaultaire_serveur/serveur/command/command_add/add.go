package commandadd

import (
	"vaultaire/serveur/command/display"
	"vaultaire/serveur/database"
	"vaultaire/serveur/logs"
)

// Add_Command processes the add command for adding groups or permissions to users, groups, or clients.
// It takes a slice of strings as input, which represents the command and its arguments.
// Depending on the first argument, it calls the appropriate parser function to handle the command.
// If the command is valid, it returns a string with the result of the operation.
func Add_Command(command_list []string, sender_groupsIDs []int, action, sender_Username string) string {
	switch command_list[0] {
	case "-h", "help", "--help":
		return (`
add
Ajoute des groupes ou des permissions aux utilisateurs, groupes ou clients.

add -u (Ajouter une permission ou un groupe à un utilisateur)
add -u "username" -p "permission_name"
add -u "username" -g "group_name"
add -c (Ajouter un client à un groupe ou une permission)
add -c "computeur_id" -g "group_name"
add -c "computeur_id" -p "permission_name"
add -g (Ajouter une permission à un groupe)
add -g "group_name" -p "permission_name"
`)
	case "-u":
		return add_User_Command_Parser(command_list, sender_groupsIDs, action, sender_Username)
	case "-c":
		return add_Client_Command_Parser(command_list, sender_groupsIDs, action, sender_Username)
	case "-gu", "-gc":
		return add_group_Command_Parser(command_list, sender_groupsIDs, action, sender_Username)
	case "-gpo":
		return add_GPO_Command_Parser(command_list, sender_groupsIDs, action, sender_Username)
	default:
		return ("Invalid Request Try get -h for more information")
	}
}

// post_displayGroupInfo retrieves the group information by its name and returns a formatted string.
// If an error occurs while retrieving the group information, it logs the error and returns an error message.
func post_displayGroupInfo(groupName string) string {
	groupInfo, err := database.Command_GET_GroupInfo(database.GetDatabase(), groupName)
	if err != nil {
		logs.Write_Log("WARNING", "Error for get group by id "+groupName+": "+err.Error())
		return (">> -" + err.Error())
	}
	return display.DisplayGroupInfo(groupInfo)
}
