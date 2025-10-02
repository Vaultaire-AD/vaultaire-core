package commandget

import (
	commandpermission "DUCKY/serveur/command/command_permission"
	"DUCKY/serveur/command/display"
	"DUCKY/serveur/database"
	"DUCKY/serveur/logs"
	"DUCKY/serveur/permission"
	"fmt"
)

// getGroupCommandParser traite les commandes "get group"
func getGroupCommandParser(commandList []string, senderGroupsIDs []int, action, senderUsername string) string {
	if len(commandList) == 1 && commandList[0] == "-g" {
		return handleGetAllGroups(senderGroupsIDs, action, senderUsername)
	}

	if len(commandList) == 2 && commandList[0] == "-g" {
		groupName := commandList[1]
		return handleGetGroupByName(groupName, senderGroupsIDs, action, senderUsername)
	}

	if len(commandList) == 3 {
		targetType, groupName := commandList[1], commandList[2]
		switch targetType {
		case "-u":
			return handleGetUsersByGroup(groupName, senderGroupsIDs, action, senderUsername)
		case "-c":
			return handleGetClientsByGroup(groupName, senderGroupsIDs, action, senderUsername)
		default:
			return invalidGroupRequest()
		}
	}

	return invalidGroupRequest()
}

// --- Fonctions privées --- //

func handleGetAllGroups(senderGroupsIDs []int, action, senderUsername string) string {
	if !commandpermission.CheckAccess(senderGroupsIDs, action, senderUsername, []string{"*"}) {
		return fmt.Sprintf("Permission refusée pour %s sur %s", senderUsername, action)
	}
	groups, err := database.Command_GET_GroupDetails(database.GetDatabase())
	if err != nil {
		logs.Write_Log("WARNING", "Erreur lors de la récupération de tous les groupes : "+err.Error())
		return ">> -" + err.Error()
	}
	return display.DisplayGroupDetails(groups)
}

func handleGetGroupByName(groupName string, senderGroupsIDs []int, action, senderUsername string) string {
	domains, err := permission.GetDomainsFromGroupName(groupName)
	if err != nil {
		return fmt.Sprintf(">> -Erreur lors de la récupération des domaines du groupe %s : %s", groupName, err.Error())
	}
	if !commandpermission.CheckAccess(senderGroupsIDs, action, senderUsername, domains) {
		return fmt.Sprintf("Permission refusée pour %s sur %s", senderUsername, action)
	}
	group, err := database.Command_GET_GroupInfo(database.GetDatabase(), groupName)
	if err != nil {
		logs.Write_Log("WARNING", fmt.Sprintf("Erreur lors de la récupération du groupe %s : %s", groupName, err.Error()))
		return ">> -" + err.Error()
	}
	return display.DisplayGroupInfo(group)
}

func handleGetUsersByGroup(groupName string, senderGroupsIDs []int, action, senderUsername string) string {
	domains, err := permission.GetDomainsFromGroupName(groupName)
	if err != nil {
		return fmt.Sprintf(">> -Erreur lors de la récupération des domaines du groupe %s : %s", groupName, err.Error())
	}
	if !commandpermission.CheckAccess(senderGroupsIDs, action, senderUsername, domains) {
		return fmt.Sprintf("Permission refusée pour %s sur %s", senderUsername, action)
	}
	users, err := database.Command_GET_UsersByGroup(database.GetDatabase(), groupName)
	if err != nil {
		logs.Write_Log("WARNING", fmt.Sprintf("Erreur lors de la récupération des utilisateurs du groupe %s : %s", groupName, err.Error()))
		return ">> -" + err.Error()
	}
	return display.DisplayUsersByGroup(groupName, users)
}

func handleGetClientsByGroup(groupName string, senderGroupsIDs []int, action, senderUsername string) string {
	domains, err := permission.GetDomainsFromGroupName(groupName)
	if err != nil {
		return fmt.Sprintf(">> -Erreur lors de la récupération des domaines du groupe %s : %s", groupName, err.Error())
	}
	if !commandpermission.CheckAccess(senderGroupsIDs, action, senderUsername, domains) {
		return fmt.Sprintf("Permission refusée pour %s sur %s", senderUsername, action)
	}
	clients, err := database.Command_GET_ClientsByGroup(database.GetDatabase(), groupName)
	if err != nil {
		logs.Write_Log("WARNING", fmt.Sprintf("Erreur lors de la récupération des clients du groupe %s : %s", groupName, err.Error()))
		return ">> -" + err.Error()
	}
	return display.DisplayClientsByGroup(clients, groupName)
}

func invalidGroupRequest() string {
	return "Invalid Request. Try `get -h` for more information."
}
