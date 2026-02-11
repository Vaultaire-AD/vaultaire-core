package commandremove

import (
	"vaultaire/serveur/command/display"
	"vaultaire/serveur/database"
	"vaultaire/serveur/logs"
)

// Remove_Command : clé RBAC write:delete:user, write:delete:client, write:delete:group selon sous-commande.
func Remove_Command(command_list []string, sender_groupsIDs []int, sender_Username string) string {
	actionKey := "write:delete:group"
	switch command_list[0] {
	case "-h", "help", "--help":
		return ("LOOK MAN")
	case "-u":
		actionKey = "write:delete:user"
		return remove_User_Command_Parser(command_list, sender_groupsIDs, actionKey, sender_Username)
	case "-c":
		actionKey = "write:delete:client"
		return remove_Client_Command_Parser(command_list, sender_groupsIDs, actionKey, sender_Username)
	case "-g":
		actionKey = "write:delete:group"
		return remove_Group_Command_Parser(command_list, sender_groupsIDs, actionKey, sender_Username)
	case "-gpo":
		actionKey = "write:delete:gpo"
		return remove_GPO_Command_Parser(command_list, sender_groupsIDs, actionKey, sender_Username)
	default:
		return ("LOOK MAN")
	}
}

func post_displayGroupInfo(groupName string) string {
	groupInfo, err := database.Command_GET_GroupInfo(database.GetDatabase(), groupName)
	if err != nil {
		logs.Write_Log("WARNING", "error during the get of the group "+groupName+" : "+err.Error())
		return (">> -" + err.Error())
	}
	return display.DisplayGroupInfo(groupInfo)
}
