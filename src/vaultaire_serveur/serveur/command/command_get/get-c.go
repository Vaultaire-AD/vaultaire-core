package commandget

import (
	commandpermission "DUCKY/serveur/command/command_permission"
	"DUCKY/serveur/command/display"
	"DUCKY/serveur/database"
	"DUCKY/serveur/logs"
	"DUCKY/serveur/permission"
	"fmt"
)

func get_Client_Command_Parser(commandList []string, senderGroupsIDs []int, action, senderUsername string) string {
	db := database.GetDatabase()

	switch len(commandList) {

	// Cas 1 : afficher tous les clients
	case 1:
		if !commandpermission.CheckAccess(senderGroupsIDs, action, senderUsername, []string{"*"}) {
			return fmt.Sprintf("Permission refusée pour %s sur %s", senderUsername, action)
		}
		allClients, err := database.Command_GET_AllClients(db)
		if err != nil {
			logs.Write_Log("WARNING", "Erreur lors de la récupération de tous les clients : "+err.Error())
			return ">> -" + err.Error()
		}
		return display.DisplayAllClients(allClients)

	// Cas 2 : afficher un client spécifique par ComputeurID
	case 2:
		clientID := commandList[1]
		permissionsList, err := permission.GetDomainsFromClientByComputerID(clientID)
		if err != nil {
			return fmt.Sprintf(">> -Erreur récupération domaines pour le client %s : %s", clientID, err.Error())
		}
		if !commandpermission.CheckAccess(senderGroupsIDs, action, senderUsername, permissionsList) {
			return fmt.Sprintf("Permission refusée pour %s sur %s", senderUsername, action)
		}
		client, err := database.Command_GET_ClientByComputeurID(database.DB, clientID)
		if err != nil {
			logs.Write_Log("WARNING", "Erreur lors de la récupération du client "+clientID+" : "+err.Error())
			return ">> -" + err.Error()
		}
		return display.DisplaySoftware(client)

	// Cas par défaut : commande invalide
	default:
		return "Invalid Request. Try get -h for more information"
	}
}
