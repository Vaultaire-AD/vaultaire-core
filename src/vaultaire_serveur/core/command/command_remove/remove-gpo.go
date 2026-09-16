package commandremove

import (
	"vaultaire/core/action"
	commandaction "vaultaire/core/command/commandaction"
	"vaultaire/core/command/groupview"
)

// remove_GPO_Command_Parser retire la liaison entre une GPO et un groupe.
//
// La GPO elle-même n'est pas supprimée : elle reste disponible pour d'autres
// groupes (voir delete -gpo pour la supprimer définitivement).
//
// Usage : remove -gpo <nom_gpo> -g <nom_groupe>
//
// Le contrôle est passé à l'action group.remove_gpo, sur l'union des domaines
// du groupe et de la GPO — voir add-gpo.go pour le raisonnement.
func remove_GPO_Command_Parser(command_list []string, sender_groupsIDs []int, _ string, sender_Username string) string {
	if len(command_list) != 4 || command_list[0] != "-gpo" || command_list[2] != "-g" {
		return "Requête invalide : remove -gpo <nom_gpo> -g <nom_groupe>"
	}

	groupName := command_list[3]
	res, err := action.Executer("group.remove_gpo",
		action.Appelant{Username: sender_Username, GroupIDs: sender_groupsIDs},
		action.Params{"gpo": command_list[1], "group": groupName})
	if err != nil {
		return commandaction.MessageDErreur(err)
	}

	return res.Message + "\n\n" + groupview.Fiche(groupName)
}
