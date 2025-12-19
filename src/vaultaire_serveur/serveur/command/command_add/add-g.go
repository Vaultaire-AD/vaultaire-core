package commandadd

import (
	"DUCKY/serveur/database"
	"DUCKY/serveur/database/db_permission"
	"DUCKY/serveur/logs"
	"DUCKY/serveur/permission"
	"fmt"
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
	ok, reason := permission.CheckPermissionsMultipleDomains(sender_groupsIDs, action, domains)
	if !ok {
		logs.Write_Log("SECURITY", fmt.Sprintf("%s tente d'ajouter permission %s au groupe %s (domaines : %v) — %s",
			sender_Username, permName, groupName, domains, reason))
		return fmt.Sprintf("Permission refusée : %s", reason)
	}

	// 🔹 Étape 3 : Ajout de la permission
	switch command_list[0] {
	case "-gu":
		err := db_permission.Command_ADD_UserPermissionToGroup(database.GetDatabase(), permName, groupName)
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
