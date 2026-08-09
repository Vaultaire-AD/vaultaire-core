package commandget

import (
	"vaultaire/core/action"
	"vaultaire/core/command/display"
	"vaultaire/core/storage"
)

// getGroupCommandParser traite « get -g … ».
//
// # Une incohérence corrigée au passage
//
// `get -g -u <groupe>` et `get -u -g <groupe>` listent la MÊME chose : les
// utilisateurs d'un groupe. Les deux chemins exigeaient pourtant des droits
// différents — `read:get:group` par ici, aucun contrôle du tout par là.
//
// Les deux appellent maintenant group.list_users, qui exige `read:get:user` :
// ce qui est révélé est une liste de COMPTES, et c'est le droit de lire des
// comptes qui doit la garder. Exiger `read:get:group` aurait laissé un délégué
// n'ayant que le droit sur les groupes énumérer des utilisateurs qu'il n'a pas
// le droit de lire un par un.
func getGroupCommandParser(commandList []string, senderGroupsIDs []int, _ string, senderUsername string) string {
	appelant := action.Appelant{Username: senderUsername, GroupIDs: senderGroupsIDs}

	if len(commandList) == 1 {
		// get -g
		return lire("group.list", appelant, action.Params{}, afficherListeGroupes)
	}

	if len(commandList) == 2 {
		// get -g <groupe>
		return lire("group.get", appelant,
			action.Params{"group": commandList[1]}, afficherFicheGroupe)
	}

	if len(commandList) == 3 {
		p := action.Params{"group": commandList[2]}
		switch commandList[1] {
		case "-u":
			return lire("group.list_users", appelant, p, afficherUtilisateursDuGroupe)
		case "-c":
			return lire("group.list_clients", appelant, p, afficherMachinesDuGroupe)
		}
	}

	return invalidGroupRequest()
}

func afficherListeGroupes(res action.Resultat) string {
	groupes, ok := res.Donnees.([]storage.GroupDetails)
	if !ok {
		return res.Message
	}
	return display.DisplayGroupDetails(groupes)
}

func afficherFicheGroupe(res action.Resultat) string {
	info, ok := res.Donnees.(*storage.GroupInfo)
	if !ok || info == nil {
		return res.Message
	}
	return display.DisplayGroupInfo(info)
}

func afficherMachinesDuGroupe(res action.Resultat) string {
	d, ok := res.Donnees.(action.MachinesDeGroupe)
	if !ok {
		return res.Message
	}
	return display.DisplayClientsByGroup(d.Machines, d.Groupe)
}

func invalidGroupRequest() string {
	return "Requête invalide. Essayez « get -h »."
}
