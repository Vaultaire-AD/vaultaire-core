package commandget

import (
	commandpermission "vaultaire/serveur/command/command_permission"
	"vaultaire/serveur/command/display"
	"vaultaire/serveur/database"
	"vaultaire/serveur/logs"
	"vaultaire/serveur/permission"
	"fmt"
)

// getGPOCommandParser traite les commandes "get gpo"
func getGPOCommandParser(commandList []string, senderGroupsIDs []int, action, senderUsername string) string {
	switch len(commandList) {
	case 1:
		if !commandpermission.CheckAccess(senderGroupsIDs, action, senderUsername, []string{"*"}) {
			return fmt.Sprintf("Permission refusée pour %s sur %s", senderUsername, action)
		}
		// Récupérer toutes les GPOs
		gpos, err := database.Command_GET_AllGPO(database.GetDatabase())
		if err != nil {
			logs.Write_Log("WARNING", "Erreur lors de la récupération de toutes les GPOs : "+err.Error())
			return ">> -" + err.Error()
		}
		return display.DisplayAllGPOs(gpos)

	case 2:
		gpoName := commandList[1]

		// Récupérer tous les domaines liés à la GPO
		domainList, err := permission.GetDomainslistFromGPO(gpoName)
		if err != nil {
			return fmt.Sprintf(">> -Erreur lors de la récupération des domaines de la GPO %s : %s", gpoName, err.Error())
		}

		// Vérifie l'accès sur tous les domaines associés
		if !commandpermission.CheckAccess(senderGroupsIDs, action, senderUsername, domainList) {
			return fmt.Sprintf("Permission refusée pour %s sur %s", senderUsername, action)
		}

		// Récupérer et afficher les détails de la GPO
		gpoDetails, err := database.Command_GET_GPOInfoByName(database.GetDatabase(), gpoName)
		if err != nil {
			logs.Write_Log("WARNING", "Erreur lors de la récupération de la GPO "+gpoName+" : "+err.Error())
			return ">> -" + err.Error()
		}
		return display.DisplayGPOByName(&gpoDetails)

	default:
		return "Invalid Request. Try `get -h` for more information."
	}
}
