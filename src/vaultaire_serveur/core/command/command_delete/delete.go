package commanddelete

import (
	"vaultaire/core/action"
	commandaction "vaultaire/core/command/commandaction"
)

// Commande « delete » — supprime une entité.
//
// # La différence avec « remove »
//
// « delete » détruit, « remove » détache. Supprimer un utilisateur retire son
// compte de l'annuaire ET le révoque sur tout le parc ; le retirer d'un groupe
// ne fait que rompre un lien.
//
// # Ce que « delete -u » fait vraiment
//
// Pas une suppression en base. L'appel direct ne retirait le compte que de
// l'annuaire : le compte LOCAL restait vivant sur chaque machine, avec son mot
// de passe dans /etc/shadow et ses clés dans authorized_keys. Le compte
// survivait donc à sa propre suppression.
//
// L'action user.delete passe par la révocation, qui nettoie les machines en
// ligne, rejoue vers celles qui sont hors ligne, et laisse une trace d'audit.

// ActionsUtilisees liste les actions du registre appelées ici.
var ActionsUtilisees = []string{
	"user.delete",
	"group.delete",
	"client.delete",
	"permission.delete",
}

// Delete_Command traite « delete … ».
func Delete_Command(command_list []string, sender_groupsIDs []int, sender_Username string) string {
	if len(command_list) == 0 {
		return aide()
	}

	switch command_list[0] {
	case "-h", "help", "--help":
		return aide()

	case "-u":
		if len(command_list) < 2 {
			return "Requête invalide : delete -u <username>"
		}
		p := action.Params{"username": command_list[1]}
		return commandaction.ExecuterAction("user.delete", p, sender_groupsIDs, sender_Username)

	case "-g":
		if len(command_list) < 2 {
			return "Requête invalide : delete -g <groupe>"
		}
		p := action.Params{"group": command_list[1]}
		return commandaction.ExecuterAction("group.delete", p, sender_groupsIDs, sender_Username)

	case "-c":
		if len(command_list) < 2 {
			return "Requête invalide : delete -c <computeur_id>"
		}
		p := action.Params{"computeur_id": command_list[1]}
		return commandaction.ExecuterAction("client.delete", p, sender_groupsIDs, sender_Username)

	case "-p":
		if len(command_list) < 2 {
			return "Requête invalide : delete -p <permission>"
		}
		p := action.Params{"permission_name": command_list[1]}
		return commandaction.ExecuterAction("permission.delete", p, sender_groupsIDs, sender_Username)

	case "-gpo":
		// Hors périmètre. Aucun contrôle ajouté ici :
		// delete_GPO_Command_Parser exige déjà le droit sur les domaines de la
		// GPO, plus précis qu'un contrôle global posé en amont.
		return delete_GPO_Command_Parser(command_list, sender_groupsIDs, "write:delete:gpo", sender_Username)

	default:
		return "Requête invalide. Essayez « delete -h »."
	}
}

func aide() string {
	return `delete — supprime une entité.

  delete -u <username>        supprime un compte et le révoque sur tout le parc
  delete -g <groupe>          supprime un groupe
  delete -c <computeur_id>    retire une machine de l'annuaire
  delete -p <permission>      supprime une permission utilisateur
  delete -gpo <gpo>           supprime une GPO

Notes :
  -u  la suppression révoque le compte sur les machines : celles qui sont hors
      ligne le nettoieront à leur reconnexion. Vous ne pouvez pas supprimer
      votre propre compte.
  -c  retire la machine de l'annuaire mais ne désinstalle PAS l'agent, qui
      reste en place sur le poste.`
}
