package commandstatus

import (
	"DUCKY/serveur/command/display"
	"DUCKY/serveur/database"
	"DUCKY/serveur/logs"
	"DUCKY/serveur/permission"
	"fmt"
)

func status_User_Command_Parser(command_list []string, sender_groupsIDs []int, action, sender_Username string) string {
	db := database.GetDatabase()

	// Cas : status -u <username>
	if len(command_list) == 2 {
		targetUser := command_list[1]

		// Récupérer les domaines de l'utilisateur cible
		userDomains, err := permission.GetDomainListFromUsername(targetUser)
		if err != nil {
			logs.Write_Log("WARNING", "Erreur récupération domaines utilisateur "+targetUser+" : "+err.Error())
			return "Erreur lors de la récupération du domaine utilisateur"
		}

		// Vérifier la permission sur ces domaines
		ok, resp := permission.CheckPermissionsMultipleDomains(sender_groupsIDs, action, userDomains)
		if !ok {
			return fmt.Sprintf("Permission refusée : %s", resp)
		}

		// Si permission OK → récupérer les infos
		users_Login, err := database.Command_STATUS_GetConnectedUser(db, targetUser)
		if err != nil {
			logs.Write_Log("WARNING", "Erreur récupération utilisateur "+targetUser+" : "+err.Error())
			return "Erreur lors de la récupération de l'utilisateur"
		}

		return display.DisplayUsersByStatus(users_Login)
	}

	// Cas : status -u -g <group_name>
	if len(command_list) == 3 && command_list[1] == "-g" {
		groupName := command_list[2]

		// Récupérer le domaine du groupe
		groupDomain, err := permission.GetDomainsFromGroupName(groupName)
		if err != nil {
			logs.Write_Log("WARNING", "Erreur récupération domaine groupe "+groupName+" : "+err.Error())
			return "Erreur lors de la récupération du domaine du groupe"
		}

		ok, resp := permission.CheckPermissionsMultipleDomains(sender_groupsIDs, action, groupDomain)
		if !ok {
			return fmt.Sprintf("Permission refusée : %s", resp)
		}

		users_Login, err := database.Command_STATUS_GetUsersByGroup(db, groupName)
		if err != nil {
			logs.Write_Log("WARNING", "Erreur récupération utilisateurs du groupe "+groupName+" : "+err.Error())
			return "Erreur lors de la récupération des utilisateurs du groupe"
		}

		return display.DisplayUsersByStatus(users_Login)
	}

	// Cas : status -u (aucun argument)
	if command_list[0] == "-u" && len(command_list) == 1 {
		// Vérification sur tous les domaines (*)
		ok, resp := permission.CheckPermissionsMultipleDomains(sender_groupsIDs, action, []string{"*"})
		if !ok {
			return fmt.Sprintf("Permission refusée : %s", resp)
		}

		Users_Login, _ := database.Command_STATUS_GetConnectedUsers(db)
		return display.DisplayUsersByStatus(Users_Login)
	}

	return "\nArgument manquant. Utilisez 'status -h' pour plus d'informations ou consultez le wiki."
}
