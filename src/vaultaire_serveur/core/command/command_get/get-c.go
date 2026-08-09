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

	default:
		return "Requête invalide. Essayez « get -h »."
	}
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
