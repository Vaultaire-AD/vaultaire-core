package commanddelete

import (
	"DUCKY/serveur/database"
	"DUCKY/serveur/logs"
	"DUCKY/serveur/permission"
	"fmt"
)

// delete_GPO_Command_Parser handles the deletion of a GPO by its name.
// Usage : delete -gpo <gpo_name>
func delete_GPO_Command_Parser(command_list []string, sender_groupsIDs []int, action, sender_Username string) string {
	db := database.GetDatabase()

	// 🔸 Vérification du format de commande
	if len(command_list) != 2 || command_list[0] != "-gpo" {
		return "Requête invalide. Utilisez : delete -gpo <nom_de_la_GPO>"
	}

	gpoName := command_list[1]

	// 🔹 Étape 1 : Récupération des domaines associés à la GPO
	domains, err := permission.GetDomainslistFromGPO(gpoName)
	if err != nil {
		logs.Write_Log("WARNING", fmt.Sprintf("Erreur récupération domaines GPO %s : %v", gpoName, err))
		return fmt.Sprintf("Erreur lors de la récupération des domaines de la GPO %s : %v", gpoName, err)
	}

	// 🔹 Étape 2 : Vérification des permissions sur les domaines concernés
	ok, reason := permission.CheckPermissionsMultipleDomains(sender_groupsIDs, action, domains)
	if !ok {
		logs.Write_Log("SECURITY", fmt.Sprintf(
			"Suppression refusée : %s tente de supprimer la GPO %s (domaines : %v) — %s",
			sender_Username, gpoName, domains, reason,
		))
		return fmt.Sprintf("Permission refusée : %s", reason)
	}

	// 🔹 Étape 3 : Suppression de la GPO
	err = database.Command_DELETE_GPOWithGPOName(db, gpoName)
	if err != nil {
		logs.Write_Log("ERROR", fmt.Sprintf("Erreur suppression GPO %s : %v", gpoName, err))
		return fmt.Sprintf("Erreur lors de la suppression de la GPO %s : %v", gpoName, err)
	}

	// 🔹 Étape 4 : Vérification si GPO encore présente
	_, err = database.Command_GET_GPOInfoByName(db, gpoName)
	if err == nil {
		return fmt.Sprintf("La GPO %s semble encore exister après suppression.", gpoName)
	}

	// 🔹 Étape 5 : Journalisation et confirmation
	logs.Write_Log("INFO", fmt.Sprintf("GPO '%s' supprimée avec succès par %s", gpoName, sender_Username))
	return fmt.Sprintf("GPO '%s' supprimée avec succès.", gpoName)
}
