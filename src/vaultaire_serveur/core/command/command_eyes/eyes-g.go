package commandeyes

import (
	"strings"

	"vaultaire/core/action"
	commandaction "vaultaire/core/command/commandaction"
	"vaultaire/core/command/display"
	"vaultaire/core/storage"
)

// eyes_by_domain affiche l'arborescence des domaines et de leurs groupes.
//
//	eyes -g              arborescence complète, réduite au périmètre
//	eyes -g <domaine>    groupes situés sous un domaine
//
// # Ce qui a changé
//
// La commande exigeait la clé passée par son appelant — « write:eyes », un
// droit d'ÉCRITURE pour une commande qui ne fait que lire. Elle exige
// désormais `read:get:group`, comme `get -g` : c'est la même donnée sous une
// autre présentation, et voir des groupes en arbre n'apprend rien de plus que
// les voir en tableau.
//
// L'arborescence est aussi RÉDUITE au périmètre de l'appelant. Un délégué de
// paris voyait auparavant la structure de toute l'organisation — quels
// domaines existent, comment ils s'emboîtent — ce que la liste des groupes ne
// lui montrait pas. Les deux vues disent maintenant la même chose.
func eyes_by_domain(command_list []string, sender_groupsIDs []int, _ string, sender_Username string) string {
	appelant := action.Appelant{Username: sender_Username, GroupIDs: sender_groupsIDs}

	// eyes -g <domaine>
	if len(command_list) == 2 {
		res, err := action.Executer("domain.list_groups", appelant,
			action.Params{"domain": command_list[1]})
		if err != nil {
			return commandaction.MessageDErreur(err)
		}
		groupes, ok := res.Donnees.([]string)
		if !ok || len(groupes) == 0 {
			return res.Message
		}
		var sb strings.Builder
		sb.WriteString("Groupes sous " + command_list[1] + " :\n")
		for _, g := range groupes {
			sb.WriteString("  - " + g + "\n")
		}
		return sb.String()
	}

	// eyes -g
	res, err := action.Executer("domain.list_tree", appelant, action.Params{})
	if err != nil {
		return commandaction.MessageDErreur(err)
	}

	groupes, ok := res.Donnees.([]storage.GroupDomain)
	if !ok || len(groupes) == 0 {
		return res.Message
	}

	// L'arbre est bâti APRÈS filtrage, à partir de ce que l'appelant a le
	// droit de voir. Le bâtir avant afficherait des branches masquées ensuite,
	// ou pire, des domaines vides dont l'existence même est une information.
	arbre := display.PrintDomainTreeRoot(action.ArbreDepuis(groupes))
	if arbre == "" {
		return res.Message
	}

	// Le message porte le décompte des entrées masquées ; il précède l'arbre
	// plutôt que de le suivre, pour qu'une vue partielle s'annonce avant d'être
	// lue.
	return res.Message + "\n\n" + arbre
}
