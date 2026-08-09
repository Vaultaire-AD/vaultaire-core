package commandadd

import (
	"fmt"

	"vaultaire/core/command/groupview"
	"vaultaire/core/database"
	dbgpo "vaultaire/core/database/db_gpo"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
)

// add_GPO_Command_Parser lie une GPO à un groupe.
//
// Usage : add -gpo <nom_gpo> -g <nom_groupe>
//
// Une GPO ne se rattache qu'à des groupes, jamais à un utilisateur ni à une
// machine directement : le groupe porte déjà le domaine, les membres et les
// permissions, ce qui garde un seul point de vérité pour la portée.
func add_GPO_Command_Parser(command_list []string, sender_groupsIDs []int, action, sender_Username string) string {
	if len(command_list) != 4 || command_list[0] != "-gpo" || command_list[2] != "-g" {
		return "Invalid Request. Usage: add -gpo <gpo_name> -g <group_name>"
	}

	gpoName := command_list[1]
	groupName := command_list[3]

	// Domaines du groupe cible : c'est là que la GPO va prendre effet.
	domains, err := permission.GetDomainsFromGroupName(groupName)
	if err != nil {
		logs.Write_Log("WARNING", fmt.Sprintf("Erreur récupération domaines du groupe %s : %v", groupName, err))
		return fmt.Sprintf("Erreur récupération domaines du groupe %s : %v", groupName, err)
	}

	ok, reason := permission.CheckPermissionsAllDomains(sender_groupsIDs, action, domains)
	if !ok {
		logs.Write_Log("WARNING", fmt.Sprintf("Permission refused: user=%s action=%s gpo=%s group=%s reason=%s", sender_Username, action, gpoName, groupName, reason))
		logs.Write_Log("SECURITY", fmt.Sprintf("%s tente de lier la GPO %s au groupe %s (domaines : %v) — %s", sender_Username, gpoName, groupName, domains, reason))
		return fmt.Sprintf("Permission refusée : %s", reason)
	}
	logs.Write_Log("INFO", fmt.Sprintf("Permission used: user=%s action=%s (add gpo)", sender_Username, action))

	if err := dbgpo.LinkPolicyToGroup(database.GetDatabase(), gpoName, groupName); err != nil {
		logs.Write_Log("WARNING", fmt.Sprintf("Erreur liaison GPO %s au groupe %s : %v", gpoName, groupName, err))
		return ">> -" + err.Error()
	}

	logs.Write_Log("INFO", fmt.Sprintf("GPO %s liée au groupe %s avec succès", gpoName, groupName))
	return groupview.Fiche(groupName)
}
