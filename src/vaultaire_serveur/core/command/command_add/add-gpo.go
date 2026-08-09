package commandadd

import (
	"vaultaire/core/action"
	commandaction "vaultaire/core/command/commandaction"
	"vaultaire/core/command/groupview"
)

// add_GPO_Command_Parser lie une GPO à un groupe.
//
// Usage : add -gpo <nom_gpo> -g <nom_groupe>
//
// Une GPO ne se rattache qu'à des groupes, jamais à un utilisateur ni à une
// machine directement : le groupe porte déjà le domaine, les membres et les
// permissions, ce qui garde un seul point de vérité pour la portée.
//
// # Le contrôle a changé de main, et de portée
//
// Il vivait ici, sur les domaines du GROUPE seuls. Il est maintenant dans
// l'action group.add_gpo, sur l'UNION des domaines du groupe et de la GPO.
//
// La raison est dans PorteeGPOEtGroupe : n'exiger que le groupe laissait un
// délégué de paris lier une GPO de lyon à l'un de ses groupes. La GPO couvrait
// alors paris ET lyon, et l'administrateur de lyon ne pouvait plus modifier sa
// propre GPO sans le droit sur paris. Pas une élévation de privilège — un
// verrouillage.
func add_GPO_Command_Parser(command_list []string, sender_groupsIDs []int, _ string, sender_Username string) string {
	if len(command_list) != 4 || command_list[0] != "-gpo" || command_list[2] != "-g" {
		return "Requête invalide : add -gpo <nom_gpo> -g <nom_groupe>"
	}

	groupName := command_list[3]
	res, err := action.Executer("group.add_gpo",
		action.Appelant{Username: sender_Username, GroupIDs: sender_groupsIDs},
		action.Params{"gpo": command_list[1], "group": groupName})
	if err != nil {
		return commandaction.MessageDErreur(err)
	}

	return res.Message + "\n\n" + groupview.Fiche(groupName)
}
