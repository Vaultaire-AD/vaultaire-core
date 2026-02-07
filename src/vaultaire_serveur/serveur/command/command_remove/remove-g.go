package commandremove

import (
	"vaultaire/serveur/command/display"
	"vaultaire/serveur/database"
	"vaultaire/serveur/logs"
	"vaultaire/serveur/permission"
	"fmt"
)

func remove_Group_Command_Parser(command_list []string, sender_groupsIDs []int, action, sender_Username string) string {
	if len(command_list) != 4 {
		return "Invalid Request. Try remove -g <group_name> -pc|-pu <permission_name> or get -h for more information"
	}

	groupName := command_list[1]
	argType := command_list[2]
	permissionName := command_list[3]

	// 🔹 Étape 1 : Récupération des domaines du groupe cible
	domains, err := permission.GetDomainsFromGroupName(groupName)
	if err != nil {
		logs.Write_Log("WARNING", fmt.Sprintf("Erreur récupération domaines du groupe %s : %v", groupName, err))
		return fmt.Sprintf("Erreur récupération domaines du groupe %s : %v", groupName, err)
	}

	// 🔹 Étape 2 : Vérification des permissions du sender sur ces domaines
	ok, reason := permission.CheckPermissionsMultipleDomains(sender_groupsIDs, action, domains)
	if !ok {
		logs.Write_Log("SECURITY", fmt.Sprintf("%s tente de retirer %s du groupe %s (domaines : %v) — %s",
			sender_Username, permissionName, groupName, domains, reason))
		return fmt.Sprintf("Permission refusée : %s", reason)
	}

	var errRemove error
	switch argType {
	case "-pc":
		errRemove = database.Command_Remove_ClientPermissionFromGroup(database.GetDatabase(), groupName, permissionName)
	case "-pu":
		errRemove = database.Command_Remove_UserPermissionFromGroup(database.GetDatabase(), groupName, permissionName)
	default:
		return "Invalid argument. Use -pc for client permission or -pu for user permission"
	}

	if errRemove != nil {
		logs.Write_Log("WARNING", fmt.Sprintf("Erreur lors de la suppression de %s du groupe %s : %v", permissionName, groupName, errRemove))
		return ">> -" + errRemove.Error()
	}

	groupInfo, err := database.Command_GET_GroupInfo(database.GetDatabase(), groupName)
	if err != nil {
		logs.Write_Log("WARNING", fmt.Sprintf("Erreur récupération info groupe %s : %v", groupName, err))
		return ">> -" + err.Error()
	}

	logs.Write_Log("INFO", fmt.Sprintf("%s retiré du groupe %s avec succès", permissionName, groupName))
	return display.DisplayGroupInfo(groupInfo)
}
