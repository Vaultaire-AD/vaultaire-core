package action

import (
	"fmt"
	"strings"

	"vaultaire/core/database"
	dbpermission "vaultaire/core/database/db_permission"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
	"vaultaire/core/storage"
)

// Grammaire des actions RBAC d'une permission.
//
// C'est l'opération la plus lourde de l'annuaire : elle ne modifie pas une
// donnée, elle modifie CE QUE LES GENS ONT LE DROIT DE FAIRE. Elle était la
// dernière écriture à vivre en double, une copie par façade — et les deux
// copies avaient divergé sur trois points, chacun dans le sens du moins
// strict côté ligne de commande.
//
// # Les trois divergences, et laquelle l'emporte
//
//  1. VALIDATION DE LA CLÉ. La ligne de commande acceptait toute clé de forme
//     « catégorie:action:objet » (permission.IsValidAction). Le web exigeait en
//     plus qu'elle figure parmi les actions RÉELLEMENT administrables. Une clé
//     bien formée mais inconnue du moteur RBAC s'insérait donc en base par la
//     ligne de commande, n'y était jamais évaluée, et restait invisible : la
//     fiche affichait un droit qui n'accordait rien.
//     → La version stricte l'emporte.
//
//  2. ACTIONS GLOBALES PAR NATURE. `web_admin` et les autres clés listées par
//     permission.IsGlobalOnlyAction ne s'évaluent que sur « * » : leur donner
//     une liste de domaines les REFUSE au lieu de les restreindre. Le web
//     l'interdisait ; la ligne de commande l'acceptait.
//     Conséquence concrète : `update -pu <perm> web_admin -a 0 paris` retirait
//     l'accès à l'interface d'administration à tous les groupes portant cette
//     permission — y compris à l'auteur du changement, qui n'avait alors plus
//     l'interface pour revenir en arrière.
//     → L'interdiction l'emporte.
//
//  3. RETRAIT D'UN DOMAINE ABSENT. UpdatePermissionAction est silencieux sur un
//     domaine qu'elle ne trouve pas. Le web vérifiait la présence avant de
//     retirer ; la ligne de commande annonçait « domaine retiré » sans que rien
//     n'ait changé — une faute de frappe passait pour un succès.
//     → La vérification l'emporte.
//
// # Et une divergence dans l'autre sens
//
// La ligne de commande JOURNALISAIT les échecs d'écriture puis rendait la fiche
// comme si de rien n'était : l'utilisateur lisait un compte rendu de succès sur
// une écriture qui avait échoué. Ici les erreurs remontent.

// EnregistrerActionsGrammairePermission ajoute permission.update_action.
func EnregistrerActionsGrammairePermission(r *Registre) {
	r.MustEnregistrer(Definition{
		Nom:      "permission.update_action",
		CleRBAC:  "write:update:permission",
		Portee:   porteePermissionUtilisateur,
		Resume:   "règle une action RBAC d'une permission (nil, all, ajout ou retrait d'un domaine)",
		Executer: reglerActionPermission,
	})
}

// Opérations acceptées par permission.update_action.
//
// Nommées ici plutôt que comparées à des littéraux dispersés : les deux façades
// employaient des mots différents pour la même chose — « -a » et « -r » en
// ligne de commande, « add » et « remove » sur le web. Les deux vocabulaires
// sont acceptés en entrée et ramenés à ceux-ci.
const (
	OpPermissionNil     = "nil"
	OpPermissionAll     = "all"
	OpPermissionAjout   = "add"
	OpPermissionRetrait = "remove"
)

// normaliserOperation ramène les deux vocabulaires à un seul.
//
// La ligne de commande écrivait « -a »/« -r », le web « add »/« remove ». Les
// traduire ici plutôt que d'imposer un vocabulaire unique évite de casser la
// syntaxe que les administrateurs ont dans leurs scripts.
func normaliserOperation(op string) (string, bool) {
	switch strings.TrimSpace(op) {
	case "nil":
		return OpPermissionNil, true
	case "all":
		return OpPermissionAll, true
	case "-a", "add":
		return OpPermissionAjout, true
	case "-r", "remove":
		return OpPermissionRetrait, true
	default:
		return "", false
	}
}

// ActionPermissionAdministrable dit si une clé peut être réglée sur une
// permission.
//
// Exportée parce que l'interface web s'en sert pour construire sa matrice : la
// duplication de cette liste était l'une des trois divergences constatées.
// Une clé bien formée mais absente d'ici n'est jamais évaluée par le moteur
// RBAC — l'écrire en base produit un droit qui n'accorde rien et ne se voit pas.
func ActionPermissionAdministrable(cle string) bool {
	cle = strings.TrimSpace(cle)
	if permission.IsRBACActionKey(cle) {
		return true
	}
	for _, k := range permission.LegacyActionKeys() {
		if k == cle {
			return true
		}
	}
	for _, k := range permission.SpecialActionKeys() {
		if k == cle {
			return true
		}
	}
	return false
}

// domaineAccorde dit si un domaine figure déjà dans le mode de propagation visé.
func domaineAccorde(pa storage.PermissionAction, domaine, propagation string) bool {
	liste := pa.WithoutPropagation
	if propagation == "1" {
		liste = pa.WithPropagation
	}
	for _, d := range liste {
		if d == domaine {
			return true
		}
	}
	return false
}

// reglerActionPermission applique une opération à une action d'une permission.
//
// Paramètres :
//
//	permission_name  nom de la permission utilisateur
//	field            clé de l'action RBAC (« read:get:user », « web_admin »…)
//	op               nil | all | add | remove (ou -a | -r)
//	domain           domaine visé, pour add et remove
//	propagation      "1" avec propagation aux sous-domaines, "0" sinon
func reglerActionPermission(a Appelant, p Params) (Resultat, error) {
	nom := p.Get("permission_name")
	champ := p.Get("field")
	domaine := p.Get("domain")
	propagation := p.Get("propagation")
	if propagation == "" {
		propagation = "0"
	}

	if nom == "" {
		return Resultat{}, fmt.Errorf("nom de permission requis")
	}

	op, connue := normaliserOperation(p.Get("op"))
	if !connue {
		return Resultat{}, fmt.Errorf(
			"opération %q inconnue : attendu nil, all, add (-a) ou remove (-r)", p.Get("op"))
	}

	// Divergence 1 : la clé doit être réellement administrable.
	if !ActionPermissionAdministrable(champ) {
		logs.Write_Log("SECURITY", fmt.Sprintf(
			"%s tente d'écrire l'action inconnue %q sur la permission %s",
			a.Username, champ, nom))
		return Resultat{}, fmt.Errorf(
			"action %q inconnue : elle ne serait jamais évaluée par le moteur de droits", champ)
	}

	// Divergence 2 : une action globale par nature n'accepte que nil ou all.
	//
	// Le refus est ici et non dans le seul formulaire : l'interface ne doit
	// jamais être la seule barrière, sinon la ligne de commande la contourne —
	// ce qui était exactement le cas.
	if permission.IsGlobalOnlyAction(champ) && (op == OpPermissionAjout || op == OpPermissionRetrait) {
		return Resultat{}, fmt.Errorf(
			"l'action %s s'évalue sur tous les domaines : elle accepte seulement nil ou all. "+
				"Lui donner une liste de domaines la refuserait au lieu de la restreindre", champ)
	}

	if (op == OpPermissionAjout || op == OpPermissionRetrait) && domaine == "" {
		return Resultat{}, fmt.Errorf("domaine requis pour %s", op)
	}

	db := database.GetDatabase()

	permID, err := dbpermission.Command_GET_UserPermissionID(db, nom)
	if err != nil {
		return Resultat{}, fmt.Errorf("permission %q introuvable : %w", nom, err)
	}

	courant, err := dbpermission.Command_GET_UserPermissionAction(db, permID, champ)
	if err != nil {
		// Remontée, et non journalisation suivie d'un compte rendu de succès.
		// Sans la valeur actuelle, un ajout de domaine écraserait les domaines
		// déjà accordés au lieu de s'y ajouter.
		return Resultat{}, fmt.Errorf("lecture de l'action %s impossible : %w", champ, err)
	}
	analyse := permission.ParsePermissionAction(courant)

	var nouvelle, message string
	switch op {
	case OpPermissionNil:
		nouvelle = "nil"
		message = fmt.Sprintf("Action %s mise à nil sur %s : plus aucun domaine.", champ, nom)

	case OpPermissionAll:
		nouvelle = "all"
		message = fmt.Sprintf("Action %s mise à all sur %s : tous les domaines.", champ, nom)

	case OpPermissionAjout:
		permission.UpdatePermissionAction(&analyse, domaine, propagation, true)
		nouvelle = permission.ConvertPermissionActionToString(analyse)
		message = fmt.Sprintf("Domaine %s ajouté à %s sur %s.", domaine, champ, nom)

	case OpPermissionRetrait:
		// Divergence 3 : le domaine doit être réellement accordé.
		if !domaineAccorde(analyse, domaine, propagation) {
			return Resultat{}, fmt.Errorf(
				"le domaine %s n'est pas accordé sur %s (mode de propagation %q) : rien à retirer",
				domaine, champ, propagation)
		}
		permission.UpdatePermissionAction(&analyse, domaine, propagation, false)

		// Plus aucun domaine : l'action passe à nil plutôt que de conserver une
		// liste vide. Les deux se lisent pareil pour le moteur, mais « nil » se
		// lit « refusé » dans la fiche, alors qu'une liste vide ressemble à une
		// donnée manquante.
		nouvelle = "nil"
		if len(analyse.WithPropagation) > 0 || len(analyse.WithoutPropagation) > 0 {
			nouvelle = permission.ConvertPermissionActionToString(analyse)
		}
		message = fmt.Sprintf("Domaine %s retiré de %s sur %s.", domaine, champ, nom)
	}

	if err := dbpermission.Command_SET_UserPermissionAction(db, permID, champ, nouvelle); err != nil {
		return Resultat{}, fmt.Errorf("écriture de l'action %s impossible : %w", champ, err)
	}

	// Trace en SECURITY : modifier une permission change les droits de tous les
	// groupes qui la portent, d'un coup. Le niveau INFO de l'exécuteur suffit
	// pour savoir que l'action a eu lieu ; celui-ci sert à la retrouver en
	// filtrant sur ce qui touche aux droits.
	logs.Write_Log("SECURITY", fmt.Sprintf(
		"%s a réglé %s sur la permission %s : %q (opération %s, domaine %q, propagation %s)",
		a.Username, champ, nom, nouvelle, op, domaine, propagation))

	// La permission relue est rendue dans Donnees : le web y prend de quoi
	// rafraîchir sa matrice, la ligne de commande de quoi afficher la fiche.
	// Sans cela, les deux relisaient la base chacune de leur côté — et c'est
	// exactement cette seconde lecture qui faisait diverger les affichages.
	perm, errRelecture := dbpermission.Command_GET_UserPermissionByName(db, nom)
	if errRelecture != nil {
		// L'écriture a réussi : le dire. Signaler seulement l'échec de
		// relecture, sinon l'appelant conclut que son changement n'a pas eu
		// lieu alors qu'il est en base.
		return Resultat{Message: message +
			" (relecture impossible, l'affichage peut être en retard)"}, nil
	}

	return Resultat{Message: message, Donnees: perm}, nil
}
