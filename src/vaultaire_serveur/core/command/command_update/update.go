package commandupdate

import (
	"strings"

	"vaultaire/core/action"
	commandaction "vaultaire/core/command/commandaction"
)

// Commande « update » — modifie une entité existante.
//
// # Ce qui reste ici
//
// « -pu » et « -debug » ne passent pas encore par le registre : le premier
// manipule la structure interne des permissions RBAC — une grammaire à part
// entière, qui mérite ses propres actions plutôt qu'une traduction hâtive ; le
// second est un réglage du serveur, pas une entité de l'annuaire.
//
// Ils gardent donc leur contrôle de droits. La distinction est explicite dans
// le code plutôt que laissée à deviner.

// ActionsUtilisees liste les actions du registre appelées ici.
var ActionsUtilisees = []string{
	"user.change_password",
}

// Update_Command traite « update … ».
func Update_Command(command_list []string, sender_groupsIDs []int, sender_Username string) string {
	if len(command_list) == 0 {
		return aide()
	}

	switch command_list[0] {
	case "-h", "help", "--help":
		return aide()

	case "-u":
		// update -u <username> -p <nouveau mot de passe>
		//
		// Le mot de passe occupe tous les arguments restants : un mot de passe
		// contenant un espace serait sinon tronqué au premier, et l'utilisateur
		// ne pourrait pas se connecter avec ce qu'il croit avoir défini.
		// L'ancienne version exigeait exactement quatre éléments, ce qui
		// refusait purement et simplement ces mots de passe.
		if len(command_list) < 4 || !strings.EqualFold(command_list[2], "-p") {
			return "Requête invalide : update -u <username> -p <nouveau mot de passe>"
		}
		p := action.Params{
			"username": command_list[1],
			"password": strings.Join(command_list[3:], " "),
		}
		return commandaction.ExecuterAction("user.change_password", p, sender_groupsIDs, sender_Username)

	case "-pu":
		// Hors périmètre : la grammaire des actions RBAC mérite ses propres
		// actions. Le contrôle reste dans update_UserPermission_Command_Parser,
		// qui l'exige sur les domaines de la permission — plus précis qu'un
		// contrôle global.
		return update_UserPermission_Command_Parser(command_list, sender_groupsIDs, "write:update:permission", sender_Username)

	case "-debug":
		// Réglage du serveur, pas une entité de l'annuaire.
		return update_Debug_Command_Parser(command_list, sender_groupsIDs, "write:update:user", sender_Username)

	default:
		return "Requête invalide. Essayez « update -h »."
	}
}

func aide() string {
	return `update — modifie une entité existante.

  update -u <username> -p <nouveau mot de passe>
  update -pu <permission> <clé d'action> nil|all|-a|-r [portée] [domaine]
  update -debug <true|false>

Note : le mot de passe peut contenir des espaces, ils sont conservés.`
}
