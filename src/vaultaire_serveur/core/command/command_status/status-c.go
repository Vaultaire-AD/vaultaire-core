package commandstatus

import (
	"vaultaire/core/action"
)

// status_Client_Command_Parser traite « status -c … ».
//
//	status -c                machines connectées
//	status -c <type>         machines connectées d'un type de logiciel
//	status -c -g <groupe>    machines connectées d'un groupe
//
// Comme pour « status -u », les trois blocs de contrôle recopiés ont laissé
// place aux actions session.* — et le cas sans argument, qui exigeait le droit
// global, se contente maintenant du droit sur un domaine avec filtrage.
func status_Client_Command_Parser(command_list []string, sender_groupsIDs []int, _ string, sender_Username string) string {
	appelant := action.Appelant{Username: sender_Username, GroupIDs: sender_groupsIDs}

	switch {
	case len(command_list) == 1:
		return lireEtat("session.list_clients", appelant, action.Params{})

	case len(command_list) == 3 && command_list[1] == "-g":
		return lireEtat("session.list_clients_by_group", appelant,
			action.Params{"group": command_list[2]})

	case len(command_list) == 2:
		return lireEtat("session.list_clients_by_type", appelant,
			action.Params{"client_type": command_list[1]})
	}

	return "Requête invalide. Essayez « status -h »."
}
