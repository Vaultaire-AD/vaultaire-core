package commandcreate

import (
	"strings"

	"vaultaire/core/action"
	commandaction "vaultaire/core/command/commandaction"
	"vaultaire/core/command/display"
	"vaultaire/core/gpo"
)

// create_GPO crée une GPO vide.
//
// Usage : create -gpo <nom> --scope <machine|user> [--desc "texte"]
//
// La commande ne prend volontairement pas de commande shell : l'ancienne forme
// (--cmd / --ubuntu / --debian / --rocky) revenait à pousser du code arbitraire
// exécuté en root sur tout le parc. Les modules s'ajoutent ensuite depuis le
// catalogue, qui guide la saisie champ par champ.
//
// # Ce qui a disparu d'ici
//
// L'écriture en base et l'absence de contrôle. Car il n'y en avait AUCUN : la
// fonction ne recevait ni les groupes de l'appelant ni son nom, et créait la
// GPO sans rien vérifier. Le contrôle vivait un cran plus haut, dans
// create.go — donc à un endroit qu'un futur appelant pouvait contourner sans
// s'en apercevoir.
func create_GPO(command_list []string, senderGroupsIDs []int, senderUsername string) string {
	if len(command_list) < 2 {
		return gpoCreateUsage("nom de la GPO manquant")
	}

	p := action.Params{"gpo": command_list[1]}

	for i := 2; i < len(command_list); i++ {
		switch command_list[i] {
		case "--scope", "-s":
			if i+1 >= len(command_list) {
				return gpoCreateUsage("valeur manquante après --scope")
			}
			p["scope"] = strings.ToLower(command_list[i+1])
			i++
		case "--desc", "-d":
			if i+1 >= len(command_list) {
				return gpoCreateUsage("valeur manquante après --desc")
			}
			p["description"] = command_list[i+1]
			i++
		case "--cmd", "--ubuntu", "--debian", "--rocky":
			return ">> -L'option " + command_list[i] + " n'existe plus : une GPO ne transporte plus de commande shell.\n" +
				"   Créez la GPO puis ajoutez-y des modules du catalogue depuis /admin/gpo."
		default:
			return gpoCreateUsage("option inconnue : " + command_list[i])
		}
	}

	res, err := action.Executer("gpo.create",
		action.Appelant{Username: senderUsername, GroupIDs: senderGroupsIDs}, p)
	if err != nil {
		return commandaction.MessageDErreur(err)
	}

	if policy, ok := res.Donnees.(*gpo.Policy); ok && policy != nil {
		return res.Message + "\n\n" + display.DisplayGPOByName(policy)
	}
	return res.Message
}

// gpoCreateUsage rend le message d'usage accompagné du motif du refus.
func gpoCreateUsage(reason string) string {
	return "Erreur : " + reason + "\n" +
		"Usage : create -gpo <nom> --scope <machine|user> [--desc \"description\"]\n" +
		"   machine : appliquée à l'ordinateur (démarrage + rafraîchissement périodique)\n" +
		"   user    : appliquée à l'utilisateur après authentification\n" +
		"Les modules s'ajoutent ensuite depuis la page /admin/gpo."
}
