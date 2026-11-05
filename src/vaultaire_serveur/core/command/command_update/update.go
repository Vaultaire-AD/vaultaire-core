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
// « -pu » ne passe pas encore par le registre : il manipule la structure
// interne des permissions RBAC — une grammaire à part entière, qui mérite ses
// propres actions plutôt qu'une traduction hâtive. Il garde donc son contrôle
// de droits.
//
// « -debug » y passe (`server.get_debug`, `server.set_debug`) ; il a son
// fichier parce que c'est un réglage du serveur, pas une entité de l'annuaire.

// ActionsUtilisees liste les actions du registre appelées ici.
var ActionsUtilisees = []string{
	"user.change_password",
	"server.get_debug",
	"server.set_debug",
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
		//
		p, ok := ParamsChangementMotDePasse(command_list)
		if !ok {
			return "Requête invalide : update -u <username> [--permanent] -p <nouveau mot de passe>" +
				" — « --permanent » se place AVANT « -p »"
		}
		return commandaction.ExecuterAction("user.change_password", p, sender_groupsIDs, sender_Username)

	case "-pu":
		// Hors périmètre : la grammaire des actions RBAC mérite ses propres
		// actions. Le contrôle reste dans update_UserPermission_Command_Parser,
		// qui l'exige sur les domaines de la permission — plus précis qu'un
		// contrôle global.
		return update_UserPermission_Command_Parser(command_list, sender_groupsIDs, "write:update:permission", sender_Username)

	case "-debug":
		// Réglage du serveur, pas une entité de l'annuaire. Le droit est celui
		// de l'action appelée ; le troisième argument n'est plus lu.
		return update_Debug_Command_Parser(command_list, sender_groupsIDs, "", sender_Username)

	default:
		return "Requête invalide. Essayez « update -h »."
	}
}

func aide() string {
	return `update — modifie une entité existante.

  update -u <username> -p <nouveau mot de passe>        mot de passe PROVISOIRE (24 h)
  update -u <username> --permanent -p <mot de passe>    DÉFINITIF : compte de service
  update -pu <permission> <clé d'action> nil|all|deny|-a|-r [portée] [domaine]
  update -debug                                     affiche l'état du journal de détail
  update -debug <true|false>                        tout le serveur
  update -debug <sous-système> <off|debug|trace|defaut>
                                                    un sous-système : ldap, ducky, gpo, base

Note : le mot de passe peut contenir des espaces, ils sont conservés.`
}

// ParamsChangementMotDePasse lit « update -u <username> [--permanent] -p <mot
// de passe> ».
//
// Le drapeau se place AVANT « -p » (TO-DO 144).
//
// Les arguments sont REMIS en mots : le découpage de la console
// (SplitArgsPreserveBlocks) regroupe tout ce qui suit un « --drapeau » en un
// seul argument, pour les descriptions à espaces. « --permanent -p X »
// arrivait donc ici en deux arguments, « --permanent » et « -p X », et la
// forme documentée était refusée (recette du 28/10).
//
// Après « -p », « --permanent » en DERNIER mot est refusé : il aurait été pris
// pour la fin du mot de passe, en silence, et le compte se serait retrouvé
// avec un mot de passe provisoire que personne n'a tapé (recette du 28/10).
func ParamsChangementMotDePasse(command_list []string) (action.Params, bool) {
	args := strings.Fields(strings.Join(command_list, " "))
	if n := len(args); n > 0 && strings.EqualFold(args[n-1], "--permanent") &&
		!(n >= 3 && strings.EqualFold(args[2], "--permanent")) {
		return nil, false
	}
	permanent := false
	if len(args) >= 3 && strings.EqualFold(args[2], "--permanent") {
		permanent = true
		args = append(append([]string{}, args[:2]...), args[3:]...)
	}
	if len(args) < 4 || !strings.EqualFold(args[2], "-p") {
		return nil, false
	}
	p := action.Params{
		"username": args[1],
		"password": strings.Join(args[3:], " "),
	}
	if permanent {
		p["temporary"] = "non"
	}
	return p, true
}
