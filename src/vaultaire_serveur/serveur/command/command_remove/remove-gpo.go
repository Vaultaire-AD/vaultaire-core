package commandremove

import (
	"vaultaire/serveur/database"
	"vaultaire/serveur/logs"
	"vaultaire/serveur/permission"
	"fmt"
)

// remove_GPO_Command_Parser gère la suppression d’un GPO d’un groupe
func remove_GPO_Command_Parser(command_list []string, sender_groupsIDs []int, action, sender_Username string) string {
	if len(command_list) != 4 || command_list[0] != "-gpo" || command_list[2] != "-g" {
		return "Invalid Request. Try remove -gpo gpo_name -g group_name or get -h for more information"
	}

	gpoName := command_list[1]
	groupName := command_list[3]

	// 🔹 Étape 1 : Récupération des domaines associés au groupe
	domains, err := permission.GetDomainsFromGroupName(groupName)
	if err != nil {
		logs.Write_Log("WARNING", fmt.Sprintf("Erreur récupération domaines du groupe %s : %v", groupName, err))
		return fmt.Sprintf("Erreur récupération domaines du groupe %s : %v", groupName, err)
	}

	// 🔹 Étape 2 : Vérification des permissions du sender sur ces domaines
	ok, reason := permission.CheckPermissionsMultipleDomains(sender_groupsIDs, action, domains)
	if !ok {
		logs.Write_Log("WARNING", fmt.Sprintf("Permission refused: user=%s action=%s gpo=%s group=%s reason=%s", sender_Username, action, gpoName, groupName, reason))
		logs.Write_Log("SECURITY", fmt.Sprintf("%s tente de retirer GPO %s du groupe %s (domaines : %v) — %s", sender_Username, gpoName, groupName, domains, reason))
		return fmt.Sprintf("Permission refusée : %s", reason)
	}
	logs.Write_Log("INFO", fmt.Sprintf("Permission used: user=%s action=%s (remove gpo)", sender_Username, action))

	// 🔹 Étape 3 : Suppression du GPO du groupe
	err = database.Command_REMOVE_GPOFromGroup(database.GetDatabase(), gpoName, groupName)
	if err != nil {
		logs.Write_Log("WARNING", fmt.Sprintf("Erreur suppression du GPO %s du groupe %s : %v", gpoName, groupName, err))
		return ">> -" + err.Error()
	}

	logs.Write_Log("INFO", fmt.Sprintf("GPO %s retiré du groupe %s avec succès", gpoName, groupName))
	return post_displayGroupInfo(groupName)
}
