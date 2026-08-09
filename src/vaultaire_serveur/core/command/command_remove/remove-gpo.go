package commandremove

import (
	"fmt"

	"vaultaire/core/command/groupview"
	"vaultaire/core/database"
	dbgpo "vaultaire/core/database/db_gpo"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
)

// remove_GPO_Command_Parser retire la liaison entre une GPO et un groupe.
// La GPO elle-même n'est pas supprimée : elle reste disponible pour d'autres
// groupes (voir delete -gpo pour la supprimer définitivement).
//
// Usage : remove -gpo <nom_gpo> -g <nom_groupe>
func remove_GPO_Command_Parser(command_list []string, sender_groupsIDs []int, action, sender_Username string) string {
	if len(command_list) != 4 || command_list[0] != "-gpo" || command_list[2] != "-g" {
		return "Invalid Request. Try remove -gpo gpo_name -g group_name or get -h for more information"
	}

	gpoName := command_list[1]
	groupName := command_list[3]

	domains, err := permission.GetDomainsFromGroupName(groupName)
	if err != nil {
		logs.Write_Log("WARNING", fmt.Sprintf("Erreur récupération domaines du groupe %s : %v", groupName, err))
		return fmt.Sprintf("Erreur récupération domaines du groupe %s : %v", groupName, err)
	}

	ok, reason := permission.CheckPermissionsAllDomains(sender_groupsIDs, action, domains)
	if !ok {
		logs.Write_Log("WARNING", fmt.Sprintf("Permission refused: user=%s action=%s gpo=%s group=%s reason=%s", sender_Username, action, gpoName, groupName, reason))
		logs.Write_Log("SECURITY", fmt.Sprintf("%s tente de retirer la GPO %s du groupe %s (domaines : %v) — %s", sender_Username, gpoName, groupName, domains, reason))
		return fmt.Sprintf("Permission refusée : %s", reason)
	}
	logs.Write_Log("INFO", fmt.Sprintf("Permission used: user=%s action=%s (remove gpo)", sender_Username, action))

	if err := dbgpo.UnlinkPolicyFromGroup(database.GetDatabase(), gpoName, groupName); err != nil {
		logs.Write_Log("WARNING", fmt.Sprintf("Erreur retrait de la GPO %s du groupe %s : %v", gpoName, groupName, err))
		return ">> -" + err.Error()
	}

	logs.Write_Log("INFO", fmt.Sprintf("GPO %s retirée du groupe %s avec succès", gpoName, groupName))
	return groupview.Fiche(groupName)
}
