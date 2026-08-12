package commandupdate

import (
	"vaultaire/core/action"
	commandaction "vaultaire/core/command/commandaction"
	"vaultaire/core/command/display"
)

// update_UserPermission_Command_Parser règle une action RBAC d'une permission.
//
//	update -pu <permission> <clé d'action> nil|all|-a|-r [propagation] [domaine]
//
// # Ce qui a disparu d'ici
//
// Le contrôle du droit, la validation de la clé, celle de l'opération, la
// lecture et l'écriture en base. Tout cela vivait ici ET dans
// web_admin_pages.go, en double — et les deux copies avaient divergé sur trois
// points, chacun dans le sens du moins strict de ce côté-ci. Voir
// core/action/actions_permission_grammaire.go, qui les nomme.
//
// Le plus lourd des trois, pour mémoire : cette commande acceptait
// « update -pu <perm> web_admin -a 0 paris ». Or web_admin ne s'évalue que sur
// « * » : lui donner une liste de domaines la REFUSE au lieu de la restreindre.
// La commande retirait donc l'accès à l'interface d'administration à tous les
// groupes portant cette permission — y compris à celui qui la tapait, qui
// n'avait alors plus l'interface pour revenir en arrière. L'interface web
// l'interdisait déjà ; la ligne de commande la contournait.
//
// Cette fonction ne fait plus que traduire une syntaxe en paramètres nommés.
func update_UserPermission_Command_Parser(command_list []string, sender_groupsIDs []int, _ string, sender_Username string) string {
	if len(command_list) < 4 {
		return "Requête invalide : update -pu <permission> <clé d'action> nil|all|-a|-r [propagation] [domaine]"
	}

	p := action.Params{
		"permission_name": command_list[1],
		"field":           command_list[2],
		"op":              command_list[3],
	}

	// « -a » et « -r » attendent deux arguments de plus.
	//
	// L'ordre est celui de la commande historique — propagation puis domaine —
	// et non l'inverse : le changer casserait silencieusement les scripts
	// existants, en prenant « 0 » pour un nom de domaine.
	if op := command_list[3]; op == "-a" || op == "-r" {
		if len(command_list) != 6 {
			return "Requête invalide : update -pu <permission> <clé> " + op + " <propagation 0|1> <domaine>"
		}
		p["propagation"] = command_list[4]
		p["domain"] = command_list[5]
	}

	res, err := action.Executer("permission.update_action",
		action.Appelant{Username: sender_Username, GroupIDs: sender_groupsIDs}, p)
	if err != nil {
		return commandaction.MessageDErreur(err)
	}

	// La fiche vient des données de l'action, pas d'une seconde lecture.
	//
	// C'est ce qui empêche les deux façades de diverger : relire chacune de son
	// côté, c'était deux requêtes, deux instants, et deux affichages possibles
	// pour une même écriture.
	//
	// LES DROITS RBAC EN FONT PARTIE. Ils étaient passés à nil, et l'affichage
	// rendait alors « Droits RBAC — état : non lus (base indisponible) » : un
	// message faux, sur une fiche qui taisait justement le droit qu'on venait de
	// modifier. Confirmer le changement est pourtant la seule raison d'afficher
	// une fiche après une écriture.
	if d, ok := res.Donnees.(action.PermissionAvecActions); ok {
		return res.Message + "\n\n" +
			display.DisplayUserPermission(d.Permission, actionsPourAffichage(d.Actions))
	}
	return res.Message
}

// actionsPourAffichage convertit le type du registre vers celui du rendu.
//
// Le paquet display ne connaît pas le registre, et ne doit pas le connaître :
// lui faire importer `action` inverserait la dépendance — le rendu tirerait le
// métier — et le rendrait intestable seul.
//
// nil est propagé tel quel : l'affichage distingue « non lu » de « n'accorde
// rien », et une tranche vide dirait le second.
func actionsPourAffichage(src []action.ActionRBAC) []display.ActionRBAC {
	if src == nil {
		return nil
	}
	out := make([]display.ActionRBAC, 0, len(src))
	for _, a := range src {
		out = append(out, display.ActionRBAC{Cle: a.Cle, Valeur: a.Valeur})
	}
	return out
}
