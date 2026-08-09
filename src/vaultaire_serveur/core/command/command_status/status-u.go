package commandstatus

import (
	"vaultaire/core/action"
	commandaction "vaultaire/core/command/commandaction"
	"vaultaire/core/command/display"
	"vaultaire/core/storage"
)

// status_User_Command_Parser traite « status -u … ».
//
//	status -u                liste les utilisateurs connectés
//	status -u <compte>       état de connexion d'un compte
//	status -u -g <groupe>    utilisateurs connectés d'un groupe
//
// # Ce qui a disparu d'ici
//
// Trois blocs de contrôle recopiés, un par cas, chacun avec sa résolution de
// domaines et sa trace de journal. Ils vivent dans les actions session.*.
//
// # Le défaut corrigé
//
// `status -u` sans argument exigeait le droit sur « * », donc global. Un
// délégué de paris se voyait refuser la liste entière au lieu d'obtenir sa
// part — le même défaut que `get -c` et `get -p`, et la même correction :
// portée souple plus filtre de périmètre.
func status_User_Command_Parser(command_list []string, sender_groupsIDs []int, _ string, sender_Username string) string {
	appelant := action.Appelant{Username: sender_Username, GroupIDs: sender_groupsIDs}

	switch {
	case len(command_list) == 1:
		return lireEtat("session.list_users", appelant, action.Params{})

	case len(command_list) == 2:
		return lireEtat("session.get_user", appelant,
			action.Params{"username": command_list[1]})

	case len(command_list) == 3 && command_list[1] == "-g":
		return lireEtat("session.list_users_by_group", appelant,
			action.Params{"group": command_list[2]})
	}

	return "Requête invalide. Essayez « status -h »."
}

// lireEtat exécute une action de session et affiche ses données.
//
// Les six actions de session rendent l'un des deux types d'affichage, décidé
// par le type des données et non par l'action appelée : une action qui
// changerait de forme de retour se verrait donc immédiatement, au lieu de
// tomber dans un affichage muet.
func lireEtat(nom string, a action.Appelant, p action.Params) string {
	res, err := action.Executer(nom, a, p)
	if err != nil {
		return commandaction.MessageDErreur(err)
	}
	switch d := res.Donnees.(type) {
	case []storage.UserConnected:
		return display.DisplayUsersByStatus(d)
	case []storage.ClientConnected:
		return display.DisplayClientsByStatus(d)
	default:
		return res.Message
	}
}
