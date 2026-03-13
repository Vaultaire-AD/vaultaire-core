package commandadd

import (
	"fmt"
	"vaultaire/core/command/display"
	"vaultaire/core/database"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
)

// add_Client_Command_Parser handles the addition of a client to a group with permission checks.
func add_Client_Command_Parser(command_list []string, sender_groupsIDs []int, action, sender_Username string) string {
	if len(command_list) != 4 {
		return "\nMiss Argument get -h for more information or consult man on the wiki"
	}

	clientID := command_list[1]
	groupName := command_list[3]

	// 🔹 Étape 1 : Récupération des domaines associés au groupe cible
	domains, err := permission.GetDomainsFromGroupName(groupName)
	if err != nil {
		logs.Write_Log("WARNING", fmt.Sprintf("Erreur récupération domaines du groupe %s : %v", groupName, err))
		return fmt.Sprintf("Erreur récupération domaines du groupe %s : %v", groupName, err)
	}

	// 🔹 Étape 2 : Vérification des permissions sur les domaines
	ok, reason := permission.CheckPermissionsMultipleDomains(sender_groupsIDs, action, domains)
	if !ok {
		logs.Write_Log("WARNING", fmt.Sprintf("Permission refused: user=%s action=%s client=%s group=%s reason=%s", sender_Username, action, clientID, groupName, reason))
		logs.Write_Log("SECURITY", fmt.Sprintf("%s tente d'ajouter le client %s au groupe %s (domaines : %v) — %s", sender_Username, clientID, groupName, domains, reason))
		return fmt.Sprintf("Permission refusée : %s", reason)
	}
	logs.Write_Log("INFO", fmt.Sprintf("Permission used: user=%s action=%s (add client)", sender_Username, action))

	// 🔹 Étape 3 : Ajout du client au groupe
	switch command_list[2] {
	case "-g":
		err := database.Command_ADD_SoftwareToGroup(database.GetDatabase(), clientID, groupName)
		if err != nil {
			logs.Write_Log("WARNING", fmt.Sprintf("Erreur ajout du client %s au groupe %s : %v", clientID, groupName, err))
			return ">> -" + err.Error()
		}
		client, err := database.Command_GET_ClientByComputeurID(database.GetDatabase(), clientID)
		if err != nil {
			logs.Write_Log("WARNING", fmt.Sprintf("Erreur récupération client %s : %v", clientID, err))
			return ">> -" + err.Error()
		}
		logs.Write_Log("INFO", fmt.Sprintf("Client %s ajouté au groupe %s avec succès", clientID, groupName))
		return display.DisplaySoftware(client)
	default:
		return "\nMiss Argument get -h for more information or consult man on the wiki"
	}
}
