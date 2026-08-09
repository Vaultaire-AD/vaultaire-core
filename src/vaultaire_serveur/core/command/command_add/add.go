package commandadd

import (
	"strings"

	"vaultaire/core/action"
	commandaction "vaultaire/core/command/commandaction"
)

// Commande « add » — rattache une entité à une autre.
//
// # Ce que cette commande ne fait plus
//
// Ni contrôle de droits, ni écriture en base. Elle traduit une syntaxe en
// paramètres nommés, et rien d'autre.
//
// # Une incohérence corrigée au passage
//
// Les sous-commandes ne s'accordaient pas sur les domaines à contrôler :
//
//	add -u alice -g paris      exigeait le droit sur les domaines de l'UTILISATEUR
//	add -c poste-1 -g paris    exigeait le droit sur les domaines du GROUPE
//	interface web              exigeait le droit sur les domaines du GROUPE
//
// Un délégué de « paris » pouvait donc rattacher un compte de son domaine à un
// groupe de « lyon » — donc lui donner des droits sur lyon — depuis la ligne de
// commande, mais pas depuis l'interface web. La même intention aboutissait ou
// non selon la porte empruntée.
//
// Les actions exigent maintenant le droit sur l'UNION des deux. C'est plus
// strict que chacune des trois versions, et cela ne dépend plus de la façade.

// ActionsUtilisees liste les actions du registre appelées ici.
var ActionsUtilisees = []string{
	"group.add_user",
	"group.add_client",
	"group.add_permission",
	"group.add_client_permission",
	"user.add_key",
}

// Add_Command traite « add … ».
func Add_Command(command_list []string, sender_groupsIDs []int, sender_Username string) string {
	if len(command_list) == 0 {
		return aide()
	}

	switch command_list[0] {
	case "-h", "help", "--help":
		return aide()

	case "-u":
		return addUtilisateur(command_list, sender_groupsIDs, sender_Username)

	case "-c":
		// add -c <computeur_id> -g <groupe>
		if len(command_list) < 4 || command_list[2] != "-g" {
			return "Requête invalide : add -c <computeur_id> -g <groupe>"
		}
		p := action.Params{
			"computeur_id": command_list[1],
			"group":        command_list[3],
		}
		return commandaction.ExecuterAction("group.add_client", p, sender_groupsIDs, sender_Username)

	case "-gu":
		// add -gu <groupe> -p <permission> — permission UTILISATEUR au groupe
		if len(command_list) < 4 || command_list[2] != "-p" {
			return "Requête invalide : add -gu <groupe> -p <permission>"
		}
		p := action.Params{"group": command_list[1], "permission": command_list[3]}
		return commandaction.ExecuterAction("group.add_permission", p, sender_groupsIDs, sender_Username)

	case "-gc":
		// add -gc <groupe> -p <permission> — permission CLIENT au groupe
		if len(command_list) < 4 || command_list[2] != "-p" {
			return "Requête invalide : add -gc <groupe> -p <permission>"
		}
		p := action.Params{"group": command_list[1], "client_permission": command_list[3]}
		return commandaction.ExecuterAction("group.add_client_permission", p, sender_groupsIDs, sender_Username)

	case "-gpo":
		// Hors périmètre : les GPO gardent leur logique et leur contrôle.
		//
		// Aucune vérification n'est ajoutée ici, et c'est délibéré :
		// add_GPO_Command_Parser exige déjà le droit sur les domaines DE LA GPO.
		// Poser un contrôle global en amont l'aurait rendu plus strict qu'avant
		// — un délégué autorisé sur les domaines de la GPO aurait perdu le
		// droit de la rattacher, sans que la refonte l'ait décidé.
		return add_GPO_Command_Parser(command_list, sender_groupsIDs, "write:add:gpo", sender_Username)

	default:
		return "Requête invalide. Essayez « add -h »."
	}
}

// addUtilisateur traite « add -u », qui porte deux opérations distinctes.
func addUtilisateur(command_list []string, groupIDs []int, sender string) string {
	if len(command_list) < 4 {
		return "Requête invalide : add -u <username> -g <groupe> | -k <libellé> <clé>"
	}
	username := command_list[1]

	switch command_list[2] {
	case "-g":
		p := action.Params{"username": username, "group": command_list[3]}
		return commandaction.ExecuterAction("group.add_user", p, groupIDs, sender)

	case "-k":
		// La clé publique contient des espaces : elle occupe tous les
		// arguments restants. Prendre seulement command_list[4] tronquerait la
		// clé au premier espace, et la clé enregistrée serait inutilisable —
		// l'échec n'apparaissant qu'à la première tentative de connexion.
		if len(command_list) < 5 {
			return "Requête invalide : add -u <username> -k <libellé> <clé>"
		}
		p := action.Params{
			"username": username,
			"label":    command_list[3],
			"key":      strings.Join(command_list[4:], " "),
		}
		return commandaction.ExecuterAction("user.add_key", p, groupIDs, sender)

	default:
		return "Requête invalide : add -u <username> -g <groupe> | -k <libellé> <clé>"
	}
}

func aide() string {
	return `add — rattache une entité à une autre.

  add -u <username> -g <groupe>          ajoute un utilisateur à un groupe
  add -u <username> -k <libellé> <clé>   ajoute une clé publique SSH
  add -c <computeur_id> -g <groupe>      ajoute une machine à un groupe
  add -gu <groupe> -p <permission>       permission utilisateur au groupe
  add -gc <groupe> -p <permission>       permission client au groupe
  add -gpo <gpo> -g <groupe>             lie une GPO à un groupe

Note : rattacher une entité à un groupe exige désormais le droit sur les
domaines de l'entité ET sur ceux du groupe. Les deux sont engagés.`
}
