package commanddelete

import (
	"vaultaire/serveur/database"
	"vaultaire/serveur/database/db_permission"
	"vaultaire/serveur/logs"
	"vaultaire/serveur/permission"
	"fmt"
)

// delete_Permission_Command_Parser handles the deletion of permissions (user/client).
// Usage :
//
//	delete -u <user_permission_name>
//	delete -c <client_permission_name>
func delete_Permission_Command_Parser(command_list []string, sender_groupsIDs []int, action, sender_Username string) string {
	db := database.GetDatabase()

	// 🔸 Étape 0 : Validation de la commande
	if len(command_list) != 2 {
		return "Requête invalide. Utilisez 'delete -h' pour plus d'informations."
	}

	flag := command_list[0]
	permName := command_list[1]

	// 🔹 Étape 1 : Récupération des domaines associés à la permission ciblée
	var domains []string
	var err error

	switch flag {
	case "-u":
		domains, err = permission.GetDomainslistFromUserpermission(permName)
	case "-c":
		domains, err = permission.GetDomainslistFromClientpermission(permName)
	default:
		return "Option invalide. Utilisez -u (user) ou -c (client)."
	}

	if err != nil {
		logs.Write_Log("WARNING", fmt.Sprintf("Erreur récupération domaines pour %s : %v", permName, err))
		return fmt.Sprintf("Erreur lors de la récupération des domaines de la permission %s : %v", permName, err)
	}

	// 🔹 Étape 2 : Vérification de la permission du demandeur
	ok, reason := permission.CheckPermissionsMultipleDomains(sender_groupsIDs, action, domains)
	if !ok {
		logs.Write_Log("SECURITY", fmt.Sprintf(
			"Suppression refusée : %s tente de supprimer la permission %s (%s) — %s",
			sender_Username, permName, flag, reason,
		))
		return fmt.Sprintf("Permission refusée : %s", reason)
	}

	// 🔹 Étape 3 : Suppression selon le type
	switch flag {
	case "-u":
		err = db_permission.Command_DELETE_UserPermissionByName(db, permName)
	case "-c":
		err = db_permission.Command_DELETE_ClientPermissionByName(db, permName)
	}

	if err != nil {
		logs.Write_Log("ERROR", fmt.Sprintf("Erreur lors de la suppression de la permission %s (%s) : %v", permName, flag, err))
		return fmt.Sprintf("Erreur lors de la suppression de la permission %s : %v", permName, err)
	}

	// 🔹 Étape 4 : Journalisation
	logs.Write_Log("INFO", fmt.Sprintf("Permission %s (%s) supprimée avec succès par %s", permName, flag, sender_Username))
	return fmt.Sprintf("Permission %s supprimée avec succès.", permName)
}
