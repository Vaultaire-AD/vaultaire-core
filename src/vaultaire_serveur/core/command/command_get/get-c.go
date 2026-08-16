package commandget

import (
	"vaultaire/core/action"
	"vaultaire/core/command/display"
	"vaultaire/core/storage"
)

// get_Client_Command_Parser traite « get -c … ».
//
// # Un refus qui n'avait pas lieu d'être
//
// `get -c` exigeait le droit sur « * », c'est-à-dire le droit GLOBAL. Un
// délégué de paris — qui a pourtant le droit sur son domaine — se voyait
// refuser la liste ENTIÈREMENT, tandis que l'interface web la lui montrait
// filtrée. La façade employée décidait donc non seulement de ce qu'il voyait,
// mais de s'il voyait quelque chose.
//
// L'action exige maintenant le droit sur un domaine et filtre la liste au
// périmètre : le délégué obtient sa part au lieu d'un refus.
func get_Client_Command_Parser(commandList []string, senderGroupsIDs []int, _ string, senderUsername string) string {
	appelant := action.Appelant{Username: senderUsername, GroupIDs: senderGroupsIDs}

	switch len(commandList) {
	case 1:
		// get -c
		return lire("client.list", appelant, action.Params{}, afficherListeMachines)

	case 2:
		// get -c <computeur_id>
		return lire("client.get", appelant,
			action.Params{"computeur_id": commandList[1]}, afficherFicheMachine)

	case 3:
		// get -c <computeur_id> --targets
		//
		// Sous-vue séparée, et non une section ajoutée à la fiche.
		//
		// Les deux réponses n'exigent pas le même droit : la fiche demande
		// read:get:client sur le domaine de la machine, les cibles demandent
		// read:cluster — ce qui est révélé là est la TOPOLOGIE du cluster, pas
		// l'inventaire de la machine.
		//
		// Les fondre obligerait à choisir entre exiger les deux droits pour lire
		// une fiche, ou omettre les cibles en silence quand le second manque.
		// Séparées, l'absence de droit produit un refus qui nomme la clé.
		if commandList[2] != "--targets" && commandList[2] != "--cibles" {
			return "Option inconnue : " + commandList[2] + "\n\n" +
				"Usage : get -c <computeur_id> [--targets]"
		}
		return lire("cluster.client_targets", appelant,
			action.Params{"computeur_id": commandList[1]}, afficherCiblesMachine)

	default:
		return "Requête invalide. Essayez « get -h »."
	}
}

func afficherCiblesMachine(res action.Resultat) string {
	cibles, ok := res.Donnees.(action.CiblesClient)
	if !ok {
		return res.Message
	}
	return display.DisplayCiblesClient(
		cibles.ComputeurID, cibles.Cibles, cibles.GroupesClient, cibles.Ecartes)
}

func afficherListeMachines(res action.Resultat) string {
	clients, ok := res.Donnees.([]storage.GetClientsByPermission)
	if !ok {
		return res.Message
	}
	return display.DisplayAllClients(clients)
}

func afficherFicheMachine(res action.Resultat) string {
	client, ok := res.Donnees.(*storage.Software)
	if !ok || client == nil {
		return res.Message
	}
	return display.DisplaySoftware(client)
}
