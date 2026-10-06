package commandupdate

import (
	"strings"

	"vaultaire/core/action"
	commandaction "vaultaire/core/command/commandaction"
)

// update_Debug_Command_Parser règle — et relit — le détail du journal.
//
//	update -debug                                      affiche l'état
//	update -debug true|false                           tout le serveur
//	update -debug <sous-système> off|debug|trace|defaut
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
//
// # La forme sans argument relit l'état — TO-DO 145
//
// Elle rendait « requête invalide ». Le réglage se posait ici et ne se relisait
// que sur le portail ; avec un détail par sous-système, il fallait pouvoir
// demander « dans quel état est le journal ? » là où on le règle. La lecture
// exige `read:log`, pas `write:server` : regarder n'est pas régler.
//
// # Trois mots, donc un sous-système
//
// `update -debug ldap trace` règle un sous-système. Le nombre de mots décide,
// pas leur valeur : `update -debug true` reste le réglage général, et un nom de
// sous-système mal orthographié est refusé par l'action au lieu d'être pris
// pour un booléen.
func update_Debug_Command_Parser(commandList []string, sender_groupsIDs []int, _ string, sender_Username string) string {
	appelant := action.Appelant{Username: sender_Username, GroupIDs: sender_groupsIDs}

	var (
		nom    string
		params action.Params
	)
	switch len(commandList) {
	case 1:
		nom, params = "server.get_debug", action.Params{}
	case 2:
		nom, params = "server.set_debug", action.Params{"debug": commandList[1]}
	case 3:
		nom, params = "server.set_debug", action.Params{
			"sous_systeme": strings.ToLower(commandList[1]),
			"niveau":       strings.ToLower(commandList[2]),
		}
	default:
		return "Requête invalide : update -debug [true|false] | update -debug <sous-système> off|debug|trace|defaut"
	}

	res, err := action.Executer(nom, appelant, params)
	if err != nil {
		return commandaction.MessageDErreur(err)
	}
	return res.Message
}
