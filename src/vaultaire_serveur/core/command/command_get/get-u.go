package commandget

import (
	"strings"

	"vaultaire/core/action"
	commandpermission "vaultaire/core/command/command_permission"
	commandaction "vaultaire/core/command/commandaction"
	"vaultaire/core/command/display"
	"vaultaire/core/storage"
)

// getUserCommandParser traite « get -u … ».
//
// # Ce qui a disparu d'ici
//
// Le contrôle des droits et les requêtes. Cette fonction traduit une syntaxe
// en paramètres nommés, et rend l'affichage des données que l'action produit.
//
// # Deux défauts corrigés par le passage au registre
//
//  1. `get -u <compte>` contrôlait le droit sur les domaines de l'APPELANT :
//
//     domainList, _ := permission.GetDomainListFromUsername(senderUsername)
//
//     Toutes les autres lectures emploient les domaines de la CIBLE. Un
//     délégué de paris pouvait donc lire la fiche d'un compte de lyon — son
//     droit sur ses propres domaines suffisait, et la cible n'entrait jamais
//     dans la décision.
//
//  2. `get -u -g <groupe>` et `get -u <compte> -k` ne vérifiaient RIEN.
//     handleGetUserSubcommand n'appelait aucun contrôle : la composition de
//     n'importe quel groupe et les clés publiques de n'importe quel compte
//     étaient lisibles par quiconque atteignait la ligne de commande.
//
// Les deux disparaissent du seul fait de passer par le registre : une action
// ne peut pas oublier son contrôle, puisqu'elle ne l'écrit pas.
func getUserCommandParser(commandList []string, senderGroupsIDs []int, _ string, senderUsername string) string {
	appelant := action.Appelant{Username: senderUsername, GroupIDs: senderGroupsIDs}

	switch len(commandList) {
	case 1:
		// get -u
		return lire("user.list", appelant, action.Params{}, afficherListeUtilisateurs)

	case 2:
		// get -u <compte>
		return lire("user.get", appelant,
			action.Params{"username": commandList[1]}, afficherFicheUtilisateur)

	case 3:
		switch {
		case commandList[1] == "-g":
			// get -u -g <groupe>
			return lire("group.list_users", appelant,
				action.Params{"group": commandList[2]}, afficherUtilisateursDuGroupe)

		case commandList[2] == "-k":
			// get -u <compte> -k
			return lire("user.list_keys", appelant,
				action.Params{"username": strings.TrimSpace(commandList[1])}, afficherClesUtilisateur)
		}
	}

	return commandpermission.InvalidPermissionRequest()
}

// lire exécute une action de lecture et rend son affichage.
//
// Le même enchaînement pour chaque lecture : exécuter, traduire l'erreur si
// elle existe, sinon passer les données à l'affichage. L'écrire une fois évite
// qu'une des branches oublie le cas d'erreur — c'est court, donc facile à
// recopier de travers.
//
// L'exécution est FAITE ICI et non passée en paramètre : Go n'autorise pas à
// étaler les deux valeurs de retour d'un appel dans une liste d'arguments qui
// en contient d'autres. Vouloir écrire `lire(action.Executer(...), afficheur)`
// ne compile pas.
func lire(nom string, a action.Appelant, p action.Params, afficher func(action.Resultat) string) string {
	res, err := action.Executer(nom, a, p)
	if err != nil {
		return commandaction.MessageDErreur(err)
	}
	return afficher(res)
}

func afficherListeUtilisateurs(res action.Resultat) string {
	users, ok := res.Donnees.([]storage.GetUsers)
	if !ok {
		return res.Message
	}
	return display.DisplayAllUsers(users)
}

func afficherFicheUtilisateur(res action.Resultat) string {
	info, ok := res.Donnees.(*storage.GetUserInfoSingle)
	if !ok || info == nil {
		return res.Message
	}
	return display.DisplayUsersInfoByName(info)
}

func afficherUtilisateursDuGroupe(res action.Resultat) string {
	d, ok := res.Donnees.(action.UtilisateursDeGroupe)
	if !ok {
		return res.Message
	}
	return display.DisplayUsersByGroup(d.Groupe, d.Utilisateurs)
}

func afficherClesUtilisateur(res action.Resultat) string {
	d, ok := res.Donnees.(action.ClesUtilisateur)
	if !ok {
		return res.Message
	}
	if len(d.Cles) == 0 {
		// « Aucune clé » est une réponse, pas une erreur. L'ancienne version
		// rendait « >> -No public key found », qui se lit comme un échec — et
		// qu'elle rendait aussi quand la requête avait échoué, ce qui
		// confondait deux situations très différentes.
		return "Aucune clé publique enregistrée pour " + d.Username + "."
	}
	return display.DisplayUserPublicKeys(d.Username, d.Cles)
}
