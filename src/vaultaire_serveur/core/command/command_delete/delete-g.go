package commanddelete

import (
	"fmt"
	"vaultaire/core/database"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
)

// delete_Group_Command_Parser handles the deletion of a group by its name.
// Usage: delete -g <group_name>
func delete_Group_Command_Parser(command_list []string, sender_groupsIDs []int, action, sender_Username string) string {
	db := database.GetDatabase()

	// 🔸 Vérification du format
	if len(command_list) != 2 || command_list[0] != "-g" {
		return "Requête invalide. Utilisez : delete -g <nom_du_groupe>"
	}

	groupName := command_list[1]

	// 🔹 Étape 1 : Récupération des domaines associés au groupe
	domains, err := permission.GetDomainsFromGroupName(groupName)
	if err != nil {
		logs.Write_Log("WARNING", fmt.Sprintf("Erreur récupération domaines du groupe %s : %v", groupName, err))
		return fmt.Sprintf("Erreur lors de la récupération des domaines du groupe %s : %v", groupName, err)
	}

	// 🔹 Étape 2 : Vérification de permission sur ces domaines
	ok, reason := permission.CheckPermissionsMultipleDomains(sender_groupsIDs, action, domains)
	if !ok {
		logs.Write_Log("WARNING", fmt.Sprintf("Permission refused: user=%s action=%s group=%s reason=%s", sender_Username, action, groupName, reason))
		logs.Write_Log("SECURITY", fmt.Sprintf("Suppression refusée : %s tente de supprimer le groupe %s (domaines : %v) — %s", sender_Username, groupName, domains, reason))
		return fmt.Sprintf("Permission refusée : %s", reason)
	}
	logs.Write_Log("INFO", fmt.Sprintf("Permission used: user=%s action=%s (delete group)", sender_Username, action))

	// 🔹 Étape 3 : Suppression du groupe
	err = database.Command_DELETE_GroupWithGroupName(db, groupName)
	if err != nil {
		logs.Write_Log("ERROR", fmt.Sprintf("Erreur suppression du groupe %s : %v", groupName, err))
		return fmt.Sprintf("Erreur lors de la suppression du groupe %s : %v", groupName, err)
	}

	// 🔹 Étape 4 : Vérification que le groupe n’existe plus
	_, err = database.Command_GET_GroupInfo(db, groupName)
	if err == nil {
		return fmt.Sprintf("Le groupe %s semble encore exister après suppression.", groupName)
	}

	// 🔹 Étape 5 : Journalisation succès
	logs.Write_Log("INFO", fmt.Sprintf("Groupe '%s' supprimé avec succès par %s", groupName, sender_Username))
	return fmt.Sprintf("Le groupe '%s' a été supprimé avec succès.", groupName)
}
