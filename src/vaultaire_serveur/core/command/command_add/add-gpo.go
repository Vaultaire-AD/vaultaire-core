package commandadd

import (
	"fmt"
	"vaultaire/core/database"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
)

// add_GPO_Command_Parser handles the addition of a GPO to a group with permission checks.
func add_GPO_Command_Parser(command_list []string, sender_groupsIDs []int, action, sender_Username string) string {
	if len(command_list) != 4 {
		return "Invalid Request. Usage: add -gpo <gpo_name> -g <group_name>"
	}

	gpoName := command_list[1]
	groupName := command_list[3]

	// 🔹 Étape 1 : Récupération des domaines du groupe cible
	domains, err := permission.GetDomainsFromGroupName(groupName)
	if err != nil {
		logs.Write_Log("WARNING", fmt.Sprintf("Erreur récupération domaines du groupe %s : %v", groupName, err))
		return fmt.Sprintf("Erreur récupération domaines du groupe %s : %v", groupName, err)
	}

	// 🔹 Étape 2 : Vérification des permissions sur les domaines
	ok, reason := permission.CheckPermissionsMultipleDomains(sender_groupsIDs, action, domains)
	if !ok {
		logs.Write_Log("WARNING", fmt.Sprintf("Permission refused: user=%s action=%s gpo=%s group=%s reason=%s", sender_Username, action, gpoName, groupName, reason))
		logs.Write_Log("SECURITY", fmt.Sprintf("%s tente d'ajouter GPO %s au groupe %s (domaines : %v) — %s", sender_Username, gpoName, groupName, domains, reason))
		return fmt.Sprintf("Permission refusée : %s", reason)
	}
	logs.Write_Log("INFO", fmt.Sprintf("Permission used: user=%s action=%s (add gpo)", sender_Username, action))

	// 🔹 Étape 3 : Ajout du GPO au groupe
	err = database.Command_ADD_GPOToGroup(database.GetDatabase(), gpoName, groupName)
	if err != nil {
		logs.Write_Log("WARNING", fmt.Sprintf("Erreur ajout GPO %s au groupe %s : %v", gpoName, groupName, err))
		return ">> -" + err.Error()
	}

	logs.Write_Log("INFO", fmt.Sprintf("GPO %s ajouté au groupe %s avec succès", gpoName, groupName))
	return post_displayGroupInfo(groupName)
}
