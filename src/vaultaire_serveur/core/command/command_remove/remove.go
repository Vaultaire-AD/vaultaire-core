package commandremove

import (
	"vaultaire/core/action"
	commandaction "vaultaire/core/command/commandaction"
)

// Commande « remove » — détache une entité d'une autre.
//
// Symétrique de « add », et portée sur le même registre. Voir command_add/add.go
// pour l'incohérence de portée qui est corrigée dans les deux.
//
// # Une différence assumée avec « delete »
//
// « remove » détache, « delete » supprime. Retirer un utilisateur d'un groupe ne
// supprime pas le compte ; retirer une permission d'un groupe ne supprime pas la
// permission. La distinction est dans les noms des actions appelées —
// group.remove_user et non user.delete — et c'est ce qui empêche une commande de
// détruire ce qu'on voulait seulement dissocier.

// ActionsUtilisees liste les actions du registre appelées ici.
var ActionsUtilisees = []string{
	"group.remove_user",
	"group.remove_client",
	"group.remove_permission",
	"group.remove_client_permission",
	"user.remove_key",
}

// Remove_Command traite « remove … ».
func Remove_Command(command_list []string, sender_groupsIDs []int, sender_Username string) string {
	if len(command_list) == 0 {
		return aide()
	}

	switch command_list[0] {
	case "-h", "help", "--help":
		return aide()

	case "-u":
		return removeUtilisateur(command_list, sender_groupsIDs, sender_Username)

	case "-c":
		// remove -c <computeur_id> -g <groupe>
		if len(command_list) < 4 || command_list[2] != "-g" {
			return "Requête invalide : remove -c <computeur_id> -g <groupe>"
		}
		p := action.Params{"computeur_id": command_list[1], "group": command_list[3]}
		return commandaction.ExecuterAction("group.remove_client", p, sender_groupsIDs, sender_Username)

	case "-gu":
		// remove -gu <groupe> -p <permission>
		if len(command_list) < 4 || command_list[2] != "-p" {
			return "Requête invalide : remove -gu <groupe> -p <permission>"
		}
		p := action.Params{"group": command_list[1], "permission": command_list[3]}
		return commandaction.ExecuterAction("group.remove_permission", p, sender_groupsIDs, sender_Username)

	case "-gc":
		// remove -gc <groupe> -p <permission>
		if len(command_list) < 4 || command_list[2] != "-p" {
			return "Requête invalide : remove -gc <groupe> -p <permission>"
		}
		p := action.Params{"group": command_list[1], "client_permission": command_list[3]}
		return commandaction.ExecuterAction("group.remove_client_permission", p, sender_groupsIDs, sender_Username)

	case "-gpo":
		// Hors périmètre. Aucun contrôle ajouté ici : remove_GPO_Command_Parser
		// exige déjà le droit sur les domaines de la GPO, ce qui est plus précis
		// qu'un contrôle global posé en amont.
		return remove_GPO_Command_Parser(command_list, sender_groupsIDs, "write:delete:gpo", sender_Username)

	default:
		return "Requête invalide. Essayez « remove -h »."
	}
}

func removeUtilisateur(command_list []string, groupIDs []int, sender string) string {
	if len(command_list) < 4 {
		return "Requête invalide : remove -u <username> -g <groupe> | -k <id_clé>"
	}
	username := command_list[1]

	switch command_list[2] {
	case "-g":
		p := action.Params{"username": username, "group": command_list[3]}
		return commandaction.ExecuterAction("group.remove_user", p, groupIDs, sender)

	case "-k":
		// L'identifiant de clé est un entier, et l'action vérifie que la clé
		// appartient bien au compte visé. Sans ce contrôle, un délégué autorisé
		// sur un compte pourrait supprimer la clé d'un autre en devinant son
		// identifiant — la version précédente ne le vérifiait pas.
		p := action.Params{"username": username, "key_id": command_list[3]}
		return commandaction.ExecuterAction("user.remove_key", p, groupIDs, sender)

	default:
		return "Requête invalide : remove -u <username> -g <groupe> | -k <id_clé>"
	}
}

func aide() string {
	return `remove — détache une entité d'une autre.

  remove -u <username> -g <groupe>       retire un utilisateur d'un groupe
  remove -u <username> -k <id_clé>       retire une clé publique SSH
  remove -c <computeur_id> -g <groupe>   retire une machine d'un groupe
  remove -gu <groupe> -p <permission>    retire une permission utilisateur
  remove -gc <groupe> -p <permission>    retire une permission client
  remove -gpo <gpo> -g <groupe>          délie une GPO d'un groupe

Note : « remove » détache, il ne supprime pas. Retirer un utilisateur d'un
groupe ne supprime pas son compte — voir « delete » pour cela.`
}
