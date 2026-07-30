package commandcreate

import (
	"fmt"
	"strings"

	"vaultaire/core/command/display"
	"vaultaire/core/database"
	dbgpo "vaultaire/core/database/db_gpo"
	"vaultaire/core/gpo"
	"vaultaire/core/logs"
)

// create_GPO crée une GPO vide.
//
// Usage : create -gpo <nom> --scope <machine|user> [--desc "texte"]
//
// La commande ne prend volontairement plus de commande shell : l'ancienne forme
// (--cmd / --ubuntu / --debian / --rocky) revenait à pousser du code arbitraire
// exécuté en root sur tout le parc. Les modules s'ajoutent ensuite depuis
// l'interface web, où le catalogue guide la saisie champ par champ.
func create_GPO(command_list []string) string {
	if len(command_list) < 2 {
		return gpoCreateUsage("nom de la GPO manquant")
	}

	gpoName := command_list[1]
	scope := gpo.ScopeMachine
	scopeGiven := false
	description := ""

	for i := 2; i < len(command_list); i++ {
		switch command_list[i] {
		case "--scope", "-s":
			if i+1 >= len(command_list) {
				return gpoCreateUsage("valeur manquante après --scope")
			}
			candidate := gpo.Scope(strings.ToLower(command_list[i+1]))
			if !gpo.IsValidPolicyScope(candidate) {
				return gpoCreateUsage(fmt.Sprintf("scope %q invalide (attendu : machine ou user)", command_list[i+1]))
			}
			scope, scopeGiven = candidate, true
			i++
		case "--desc", "-d":
			if i+1 >= len(command_list) {
				return gpoCreateUsage("valeur manquante après --desc")
			}
			description = command_list[i+1]
			i++
		case "--cmd", "--ubuntu", "--debian", "--rocky":
			return ">> -L'option " + command_list[i] + " n'existe plus : une GPO ne transporte plus de commande shell.\n" +
				"   Créez la GPO puis ajoutez-y des modules du catalogue depuis /admin/gpo."
		default:
			return gpoCreateUsage("option inconnue : " + command_list[i])
		}
	}

	if !scopeGiven {
		return gpoCreateUsage("--scope est requis : une GPO est soit machine, soit user")
	}

	db := database.GetDatabase()
	if _, err := dbgpo.CreatePolicy(db, gpoName, scope, description); err != nil {
		logs.Write_Log("WARNING", "Erreur lors de la création de la GPO "+gpoName+" : "+err.Error())
		return ">> -" + err.Error()
	}

	logs.Write_Log("INFO", fmt.Sprintf("GPO créée avec succès : %s (scope %s)", gpoName, scope))
	policy, err := dbgpo.GetPolicyByName(db, gpoName)
	if err != nil {
		return ">> -" + err.Error()
	}
	return display.DisplayGPOByName(policy)
}

// gpoCreateUsage rend le message d'usage accompagné du motif du refus.
func gpoCreateUsage(reason string) string {
	return "Erreur : " + reason + "\n" +
		"Usage : create -gpo <nom> --scope <machine|user> [--desc \"description\"]\n" +
		"   machine : appliquée à l'ordinateur (démarrage + rafraîchissement périodique)\n" +
		"   user    : appliquée à l'utilisateur après authentification\n" +
		"Les modules s'ajoutent ensuite depuis la page /admin/gpo."
}
