package commandupdate

import (
	"vaultaire/core/action"
	commandaction "vaultaire/core/command/commandaction"
)

// update_Debug_Command_Parser règle le mode debug du serveur.
//
//	update -debug true|false
//
// # Le droit a changé
//
// La commande exigeait `write:update:user` — le droit de MODIFIER DES COMPTES.
// Régler le mode debug n'a rien d'une modification de compte : la clé accordait
// beaucoup plus que ce que la commande fait, et son nom ne laissait pas deviner
// qu'elle ouvrait ce réglage.
//
// Elle exige maintenant `write:server`, partagée avec la purge des sessions.
// Cette clé n'est accordée à personne tant qu'on ne l'accorde pas.
func update_Debug_Command_Parser(commandList []string, sender_groupsIDs []int, _ string, sender_Username string) string {
	if len(commandList) != 2 {
		return "Requête invalide : update -debug true|false"
	}

	res, err := action.Executer("server.set_debug",
		action.Appelant{Username: sender_Username, GroupIDs: sender_groupsIDs},
		action.Params{"debug": commandList[1]})
	if err != nil {
		return commandaction.MessageDErreur(err)
	}
	return res.Message
}
