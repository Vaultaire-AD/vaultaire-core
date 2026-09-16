package commandget

import (
	"vaultaire/core/action"
	commandpermission "vaultaire/core/command/command_permission"
	"vaultaire/core/command/display"
	"vaultaire/core/storage"
)

// getPermissionCommandParser traite « get -p … ».
//
//	get -p -u              liste les permissions utilisateur
//	get -p -c              liste les permissions client
//	get -p -u <nom>        fiche d'une permission utilisateur, actions RBAC comprises
//	get -p -c <nom>        fiche d'une permission client
//
// Comme pour les machines, les LISTES exigeaient le droit global : un délégué
// se voyait refuser la page entière alors que l'interface web la lui montrait
// filtrée. Elles se contentent maintenant du droit sur un domaine, et le
// registre réduit la liste au périmètre.
func getPermissionCommandParser(commandList []string, senderGroupsIDs []int, _ string, senderUsername string) string {
	appelant := action.Appelant{Username: senderUsername, GroupIDs: senderGroupsIDs}

	if len(commandList) < 2 {
		return commandpermission.InvalidPermissionRequest()
	}

	switch len(commandList) {
	case 2:
		switch commandList[1] {
		case "-u":
			return lire("permission.list", appelant, action.Params{}, afficherListePermissionsUtilisateur)
		case "-c":
			return lire("client_permission.list", appelant, action.Params{}, afficherListePermissionsClient)
		}

	case 3:
		p := action.Params{"permission_name": commandList[2]}
		switch commandList[1] {
		case "-u":
			return lire("permission.get", appelant, p, afficherFichePermissionUtilisateur)
		case "-c":
			return lire("client_permission.get", appelant, p, afficherFichePermissionClient)
		}
	}

	return commandpermission.InvalidPermissionRequest()
}

func afficherListePermissionsUtilisateur(res action.Resultat) string {
	perms, ok := res.Donnees.([]storage.UserPermission)
	if !ok {
		return res.Message
	}
	return display.DisplayAllUserPermissions(perms)
}

func afficherListePermissionsClient(res action.Resultat) string {
	perms, ok := res.Donnees.([]storage.ClientPermission)
	if !ok {
		return res.Message
	}
	return display.DisplayAllClientPermissions(perms)
}

func afficherFichePermissionUtilisateur(res action.Resultat) string {
	d, ok := res.Donnees.(action.PermissionAvecActions)
	if !ok {
		return res.Message
	}
	return display.DisplayUserPermission(d.Permission, actionsRBACPourAffichage(d.Actions))
}

func afficherFichePermissionClient(res action.Resultat) string {
	perm, ok := res.Donnees.(*storage.ClientPermission)
	if !ok || perm == nil {
		return res.Message
	}
	return display.DisplayClientPermission(*perm)
}

// actionsRBACPourAffichage convertit le type du registre vers celui de
// l'affichage.
//
// # Pourquoi deux types pour la même chose
//
// Le paquet display ne connaît pas le registre, et ne doit pas le connaître :
// c'est un module de rendu, employé aussi par des commandes qui n'ont rien à
// voir avec les actions. Lui faire importer `action` inverserait la dépendance
// — le rendu tirerait le métier — et rendrait display intestable seul.
//
// La conversion coûte une boucle sur une trentaine d'entrées, une fois par
// consultation. C'est le prix d'une frontière qui tient.
//
// nil est propagé tel quel : l'affichage distingue « non lu » de « n'accorde
// rien », et une liste vide dirait le second.
func actionsRBACPourAffichage(src []action.ActionRBAC) []display.ActionRBAC {
	if src == nil {
		return nil
	}
	out := make([]display.ActionRBAC, 0, len(src))
	for _, a := range src {
		out = append(out, display.ActionRBAC{Cle: a.Cle, Valeur: a.Valeur})
	}
	return out
}
