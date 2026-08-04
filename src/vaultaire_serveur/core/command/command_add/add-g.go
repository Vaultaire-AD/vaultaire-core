package commandadd

import (
	"fmt"
	"vaultaire/core/database"
	dbpermission "vaultaire/core/database/db_permission"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
)

// add_group_Command_Parser handles the addition of a user permission or client permission to a group with permission checks.
func add_group_Command_Parser(command_list []string, sender_groupsIDs []int, action, sender_Username string) string {
	if len(command_list) != 4 {
		return "\nMiss Argument get -h for more information or consult man on the wiki"
	}

	groupName := command_list[1]
	permName := command_list[3]

	// 🔹 Étape 1 : Récupération des domaines du groupe cible
	domains, err := permission.GetDomainsFromGroupName(groupName)
	if err != nil {
		logs.Write_Log("WARNING", fmt.Sprintf("Erreur récupération domaines du groupe %s : %v", groupName, err))
		return fmt.Sprintf("Erreur récupération domaines du groupe %s : %v", groupName, err)
	}

	// 🔹 Étape 2 : Vérification des permissions sur les domaines
	ok, reason := permission.CheckPermissionsAllDomains(sender_groupsIDs, action, domains)
	if !ok {
		logs.Write_Log("WARNING", fmt.Sprintf("Permission refused: user=%s action=%s permission=%s group=%s reason=%s", sender_Username, action, permName, groupName, reason))
		logs.Write_LogCode("WARNING", logs.CodeAuthPermission, fmt.Sprintf("permission denied: user=%s action=add permission=%s group=%s domains=%v reason=%s", sender_Username, permName, groupName, domains, reason))
		return fmt.Sprintf("Permission refusée : %s", reason)
	}
	logs.Write_Log("INFO", fmt.Sprintf("Permission used: user=%s action=%s (add permission to group)", sender_Username, action))

	// 🔹 Étape 3 : Ajout de la permission
	switch command_list[0] {
	case "-gu":
		err := dbpermission.Command_ADD_UserPermissionToGroup(database.GetDatabase(), permName, groupName)
		if err != nil {
			logs.Write_Log("WARNING", fmt.Sprintf("Erreur ajout user_permission %s au groupe %s : %v", permName, groupName, err))
			return ">> -" + err.Error()
		}
		logs.Write_Log("INFO", fmt.Sprintf("user_permission %s ajouté au groupe %s avec succès", permName, groupName))
	case "-gc":
		err := database.Command_ADD_PermissionToSoftwareGroup(database.GetDatabase(), permName, groupName)
		if err != nil {
			logs.Write_Log("WARNING", fmt.Sprintf("Erreur ajout client_permission %s au groupe %s : %v", permName, groupName, err))
			return ">> -" + err.Error()
		}
		logs.Write_Log("INFO", fmt.Sprintf("client_permission %s ajouté au groupe %s avec succès", permName, groupName))
	default:
		return "\nMiss Argument get -h for more information or consult man on the wiki"
	}

	return post_displayGroupInfo(groupName)
}
