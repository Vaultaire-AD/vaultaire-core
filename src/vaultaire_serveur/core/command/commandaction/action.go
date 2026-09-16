package commandaction

import (
	"errors"
	"fmt"
	"strings"

	"vaultaire/core/action"
)

// Pont entre la ligne de commande et le registre d'actions.
//
// # Ce qui change pour les commandes
//
// Une commande faisait trois choses : analyser ses arguments, vérifier les
// droits, agir sur la base. Elle n'en garde qu'une — l'analyse des arguments,
// qui est sa raison d'être, puisque c'est elle qui connaît la syntaxe
// « create -u alice paris.fr … ».
//
// Le contrôle des droits et l'effet passent au registre, partagés avec
// l'interface web. C'est ce qui empêche les deux façades de diverger comme
// elles l'ont fait sur la création d'utilisateur — où la ligne de commande
// acceptait une date invalide que le web refusait.
//
// # Pourquoi la commande ne vérifie plus les droits elle-même
//
// Le motif employé partout était :
//
//	if actionKey != "" {
//	    ok, response := permission.CheckPermissionsMultipleDomains(...)
//	    ...
//	}
//
// Deux défauts s'y logeaient. Le premier, le `if` : une clé restée vide sautait
// le contrôle — le même fail-open que côté web, moins exposé ici parce que le
// `default` du switch retourne avant, mais présent.
//
// Le second, plus discret : `CheckPermissionsMultipleDomains` se satisfait d'UN
// domaine correspondant, là où le registre emploie
// `CheckPermissionsAllDomains`, qui les exige tous. Sur « * » les deux
// coïncident, mais toute commande qui viserait un domaine précis aurait été
// plus permissive que la page web équivalente.

// ExecuterAction applique une action du registre et met le résultat en forme
// pour un terminal.
//
// # Sur la forme des messages
//
// Le texte rendu contient « Erreur » ou « Permission refusée » en cas d'échec.
// Ce n'est pas cosmétique : `deployments/pre-prod/scripts/rbac_fixture.sh`
// détecte les échecs en cherchant `erreur|refus|introuvable|invalide` dans la
// sortie de `vlt`. Changer ce vocabulaire ferait passer des échecs pour des
// succès dans ce script, silencieusement.
func ExecuterAction(nom string, params action.Params, groupIDs []int, sender string) string {
	appelant := action.Appelant{Username: sender, GroupIDs: groupIDs}

	res, err := action.Executer(nom, appelant, params)
	if err == nil {
		return res.Message
	}

	var refus *action.ErrRefusee
	if errors.As(err, &refus) {
		return "Permission refusée : " + refus.Motif
	}

	var inconnue *action.ErrInconnue
	if errors.As(err, &inconnue) {
		// Une commande qui désigne une action absente du registre est une faute
		// de programmation, pas une erreur de l'utilisateur. Le message le dit,
		// pour qu'on ne cherche pas du côté de la syntaxe saisie.
		return "Erreur interne : l'action " + inconnue.Nom + " n'est pas enregistrée."
	}

	return "Erreur : " + err.Error()
}

// ParamsDepuisPositionnels associe des arguments positionnels à des noms.
//
// # Pourquoi une fonction plutôt qu'une construction à la main
//
// Les commandes lisaient leurs arguments par indice :
//
//	username := command_list[1]
//	domain   := command_list[2]
//
// C'est ainsi qu'est né le dépassement d'indice de `create -g` : la garde
// vérifiait `len < 2` et le corps lisait l'indice 2. Une goroutine qui panique
// arrête le processus entier.
//
// Ici, les arguments manquants produisent des paramètres ABSENTS — pas une
// panique. L'action rend alors « domaine requis », un message qui désigne ce
// qu'il faut ajouter.
//
// Les arguments en trop sont ignorés : une commande qui en reçoit plus que
// prévu ne doit pas échouer sur ce seul motif, et l'action validera ce qu'elle
// a reçu.
func ParamsDepuisPositionnels(args []string, noms ...string) action.Params {
	p := action.Params{}
	for i, nom := range noms {
		if i >= len(args) {
			break
		}
		v := strings.TrimSpace(args[i])
		if v == "" {
			// Un argument vide est traité comme absent : « create -u "" paris »
			// ne doit pas créer un compte au nom vide, et l'action rendra
			// « identifiant requis ».
			continue
		}
		p[nom] = args[i]
	}
	return p
}

// FusionnerParams ajoute des valeurs nommées à un jeu de paramètres.
//
// Employée pour les options longues — « --scope machine » — que les commandes
// analysent elles-mêmes avant de compléter les positionnels.
func FusionnerParams(p action.Params, ajouts action.Params) action.Params {
	if p == nil {
		p = action.Params{}
	}
	for k, v := range ajouts {
		p[k] = v
	}
	return p
}

// MessageDErreur met en forme une erreur d'action pour un terminal.
//
// Séparée d'ExecuterAction pour les commandes qui ont besoin du Resultat —
// la création de machine lit l'identifiant produit avant de poursuivre par une
// installation à distance.
func MessageDErreur(err error) string {
	if err == nil {
		return ""
	}

	var refus *action.ErrRefusee
	if errors.As(err, &refus) {
		return "Permission refusée : " + refus.Motif
	}

	var inconnue *action.ErrInconnue
	if errors.As(err, &inconnue) {
		return "Erreur interne : l'action " + inconnue.Nom + " n'est pas enregistrée."
	}

	return "Erreur : " + err.Error()
}

// VerifierCatalogue s'assure que les actions nommées par les commandes existent.
//
// Appelée au démarrage : une commande qui désignerait une action absente
// échouerait sinon au moment où quelqu'un la tape, c'est-à-dire au plus mauvais
// moment. La liste est celle des actions employées par les commandes portées.
func VerifierCatalogue(nomsAttendus []string) error {
	var manquantes []string
	for _, nom := range nomsAttendus {
		if _, existe := action.Catalogue.Definition(nom); !existe {
			manquantes = append(manquantes, nom)
		}
	}
	if len(manquantes) > 0 {
		return fmt.Errorf("actions absentes du registre : %s", strings.Join(manquantes, ", "))
	}
	return nil
}
