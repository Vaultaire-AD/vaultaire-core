package commandget

import (
	"vaultaire/core/action"
	"vaultaire/core/command/display"
	dbgpo "vaultaire/core/database/db_gpo"
	"vaultaire/core/gpo"
)

// getGPOCommandParser traite « get -gpo … ».
//
//	get -gpo           liste les GPO visibles depuis le périmètre de l'appelant
//	get -gpo <nom>     détail d'une GPO
//
// La LECTURE des GPO passe par le registre. Leur ÉCRITURE — création,
// modification, suppression, modules — reste dans les handlers pour l'instant :
// c'est le dernier lot de la migration, tenu à part pour être éprouvé ou
// rejeté seul.
func getGPOCommandParser(commandList []string, senderGroupsIDs []int, _ string, senderUsername string) string {
	appelant := action.Appelant{Username: senderUsername, GroupIDs: senderGroupsIDs}

	switch len(commandList) {
	case 1:
		return lire("gpo.list", appelant, action.Params{}, afficherListeGPO)

	case 2:
		return lire("gpo.get", appelant,
			action.Params{"gpo": commandList[1]}, afficherFicheGPO)

	default:
		return "Requête invalide. Essayez « get -h »."
	}
}

func afficherListeGPO(res action.Resultat) string {
	policies, ok := res.Donnees.([]dbgpo.PolicySummary)
	if !ok {
		return res.Message
	}
	return display.DisplayAllGPOs(policies)
}

func afficherFicheGPO(res action.Resultat) string {
	policy, ok := res.Donnees.(*gpo.Policy)
	if !ok || policy == nil {
		return res.Message
	}
	return display.DisplayGPOByName(policy)
}
