package commandget

import (
	"fmt"

	commandpermission "vaultaire/core/command/command_permission"
	"vaultaire/core/command/display"
	"vaultaire/core/database"
	dbgpo "vaultaire/core/database/db_gpo"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
)

// getGPOCommandParser traite les commandes "get -gpo".
//
//	get -gpo             liste toutes les GPO (exige le droit sur tous les domaines)
//	get -gpo <nom>       détail d'une GPO (exige le droit sur ses domaines)
func getGPOCommandParser(commandList []string, senderGroupsIDs []int, action, senderUsername string) string {
	db := database.GetDatabase()

	switch len(commandList) {
	case 1:
		if !commandpermission.CheckAccess(senderGroupsIDs, action, senderUsername, []string{"*"}) {
			return fmt.Sprintf("Permission refusée pour %s sur %s", senderUsername, action)
		}
		policies, err := dbgpo.GetAllPolicies(db)
		if err != nil {
			logs.Write_Log("WARNING", "Erreur lors de la récupération de toutes les GPO : "+err.Error())
			return ">> -" + err.Error()
		}
		return display.DisplayAllGPOs(policies)

	case 2:
		gpoName := commandList[1]

		// Les domaines d'une GPO viennent des groupes auxquels elle est liée.
		// Une GPO sans groupe ne couvre aucun domaine : on exige alors le droit
		// global plutôt que de laisser une liste vide passer la vérification.
		domainList, err := permission.GetDomainslistFromGPO(gpoName)
		if err != nil {
			return fmt.Sprintf(">> -Erreur lors de la récupération des domaines de la GPO %s : %s", gpoName, err.Error())
		}
		if len(domainList) == 0 {
			domainList = []string{"*"}
		}
		if !commandpermission.CheckAccess(senderGroupsIDs, action, senderUsername, domainList) {
			return fmt.Sprintf("Permission refusée pour %s sur %s", senderUsername, action)
		}

		policy, err := dbgpo.GetPolicyByName(db, gpoName)
		if err != nil {
			logs.Write_Log("WARNING", "Erreur lors de la récupération de la GPO "+gpoName+" : "+err.Error())
			return ">> -" + err.Error()
		}
		return display.DisplayGPOByName(policy)

	default:
		return "Invalid Request. Try `get -h` for more information."
	}
}
