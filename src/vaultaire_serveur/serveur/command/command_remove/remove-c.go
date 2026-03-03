package commandremove

import (
	"vaultaire/serveur/command/display"
	"vaultaire/serveur/database"
	"vaultaire/serveur/logs"
	"vaultaire/serveur/permission"
	"fmt"
)

func remove_Client_Command_Parser(command_list []string, sender_groupsIDs []int, action, sender_Username string) string {
	if len(command_list) != 4 {
		return "Invalid Request. Try remove -c <client_id> -g <group_name> or get -h for more information"
	}

	clientID := command_list[1]
	argType := command_list[2]
	groupName := command_list[3]

	// 🔹 Étape 1 : Vérification si le client est protégé
	if clientID == "vaultaire" {
		return ">> you cannot delete or remove this client"
	}

	// 🔹 Étape 2 : Récupération des domaines associés aux groupes du client
	client, err := database.Command_GET_ClientByComputeurID(database.GetDatabase(), clientID)
	if err != nil {
		logs.Write_Log("WARNING", fmt.Sprintf("Erreur récupération client %s : %v", clientID, err))
		return fmt.Sprintf("Erreur récupération client %s : %v", clientID, err)
	}

	var domains []string
	for _, grp := range client.Groups {
		grpd, err := permission.GetDomainsFromGroupName(grp)
		if err != nil {
			logs.Write_Log("WARNING", fmt.Sprintf("Erreur récupération domaines du groupe %s : %v", grp, err))
			return fmt.Sprintf("Erreur récupération domaines du groupe %s : %v", grp, err)
		}
		domains = append(domains, grpd...)
	}

	// 🔹 Étape 3 : Vérification des permissions
	ok, reason := permission.CheckPermissionsMultipleDomains(sender_groupsIDs, action, domains)
	if !ok {
		logs.Write_Log("WARNING", fmt.Sprintf("Permission refused: user=%s action=%s client=%s group=%s reason=%s", sender_Username, action, clientID, groupName, reason))
		logs.Write_Log("SECURITY", fmt.Sprintf("%s tente de retirer %s du groupe %s (domaines : %v) — %s", sender_Username, clientID, groupName, domains, reason))
		return fmt.Sprintf("Permission refusée : %s", reason)
	}
	logs.Write_Log("INFO", fmt.Sprintf("Permission used: user=%s action=%s (remove client)", sender_Username, action))

	// 🔹 Étape 4 : Suppression
	switch argType {
	case "-g":
		err := database.Command_Remove_SoftwareFromGroup(database.GetDatabase(), clientID, groupName)
		if err != nil {
			logs.Write_Log("WARNING", fmt.Sprintf("Erreur lors de la suppression du client %s du groupe %s : %v", clientID, groupName, err))
			return ">> -" + err.Error()
		}
	default:
		return "Invalid argument. Use -g to specify the group"
	}

	clientInfo, err := database.Command_GET_ClientByComputeurID(database.GetDatabase(), clientID)
	if err != nil {
		logs.Write_Log("WARNING", fmt.Sprintf("Erreur récupération client %s après suppression : %v", clientID, err))
		return ">> -" + err.Error()
	}

	logs.Write_Log("INFO", fmt.Sprintf("Client %s retiré du groupe %s avec succès", clientID, groupName))
	return display.DisplaySoftware(clientInfo)
}
