package commandstatus

import (
	"DUCKY/serveur/command/display"
	"DUCKY/serveur/database"
	"DUCKY/serveur/logs"
	"DUCKY/serveur/permission"
	"fmt"
)

func status_Client_Command_Parser(command_list []string, sender_groupsIDs []int, action, sender_Username string) string {
	db := database.GetDatabase()

	// Cas : status -c (tous les clients)
	if command_list[0] == "-c" && len(command_list) == 1 {
		ok, resp := permission.CheckPermissionsMultipleDomains(sender_groupsIDs, action, []string{"*"})
		if !ok {
			return fmt.Sprintf("Permission refusée : %s", resp)
		}

		client_Login, err := database.Command_STATUS_GetClientsConnected(db)
		if err != nil {
			logs.Write_Log("WARNING", "Erreur récupération clients : "+err.Error())
			return ">> -" + err.Error()
		}
		return display.DisplayClientsByStatus(client_Login)
	}

	// Cas : status -c -g <group_name>
	if len(command_list) == 3 && command_list[1] == "-g" {
		groupName := command_list[2]

		// 🔹 Récupération du domaine du groupe
		groupDomain, err := permission.GetDomainsFromGroupName(groupName)
		if err != nil {
			logs.Write_Log("WARNING", "Erreur récupération domaine du groupe "+groupName+" : "+err.Error())
			return "Erreur lors de la récupération du domaine du groupe"
		}

		ok, resp := permission.CheckPermissionsMultipleDomains(sender_groupsIDs, action, groupDomain)
		if !ok {
			return fmt.Sprintf("Permission refusée : %s", resp)
		}

		client_Login, err := database.Command_STATUS_GetClientsConnectedByGroup(db, groupName)
		if err != nil {
			logs.Write_Log("WARNING", "Erreur récupération clients du groupe "+groupName+" : "+err.Error())
			return ">> -" + err.Error()
		}
		return display.DisplayClientsByStatus(client_Login)
	}

	// Cas : status -c <type_client>
	if len(command_list) == 2 {
		clientType := command_list[1]

		// 🔹 Vérification sur tous les domaines (les types n’ont pas de domaine explicite)
		ok, resp := permission.CheckPermissionsMultipleDomains(sender_groupsIDs, action, []string{"*"})
		if !ok {
			return fmt.Sprintf("Permission refusée : %s", resp)
		}

		Client_Login, err := database.Command_STATUS_GetClientsConnectedByLogicielType(db, clientType)
		if err != nil {
			logs.Write_Log("WARNING", "Erreur récupération clients du type "+clientType+" : "+err.Error())
			return ">> -" + err.Error()
		}
		return display.DisplayClientsByStatus(Client_Login)
	}

	return "\nArgument manquant. Utilisez 'status -h' pour plus d'informations ou consultez le wiki."
}
