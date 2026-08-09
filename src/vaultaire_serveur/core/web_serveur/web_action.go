package webserveur

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"vaultaire/core/action"
)

// Pont entre les formulaires HTML et le registre d'actions.
//
// # Ce que ce fichier remplace
//
// Chaque page d'administration portait sa propre cascade de `switch action`,
// suivie d'appels directs à la base. La correspondance entre le nom du bouton et
// la clé RBAC exigée vivait dans une table SÉPARÉE de l'action, ce qui produisait
// deux défauts liés :
//
//   - le contrôle des droits était FAIL-OPEN. Une action absente de la table
//     laissait `actionKey` vide, et le `if actionKey != ""` sautait la
//     vérification. Aucune erreur, aucun journal ;
//   - la logique métier existait en double avec la ligne de commande, et les
//     deux versions avaient divergé.
//
// Ici, le nom du bouton désigne une action du registre. Le registre porte la clé
// RBAC, la portée et la logique. Le web ne décide plus de rien : il traduit une
// requête HTTP en paramètres, et un résultat en message.
//
// # Le point sur lequel tout repose
//
// Une action inconnue de la table ci-dessous n'est PAS exécutée : elle est
// refusée. C'est l'inverse exact de l'ancien comportement, où l'inconnu passait.
//
// Ajouter un bouton sans l'y déclarer produit donc un refus visible, et non une
// opération sans contrôle.

// actionsFormulaire associe la valeur du champ « action » d'un formulaire au
// nom d'une action du registre.
//
// # Pourquoi une table et non le nom direct
//
// Les formulaires existants envoient « create_user », « add_gpo », « revoke_key ».
// Renommer ces valeurs en « user.create » dans tous les gabarits serait une
// modification à part, à faire ou non — et la faire ici mélangerait deux
// changements dans le même diff, ce qui rend la relecture plus difficile et le
// retour en arrière plus risqué.
//
// La table est donc la trace d'une transition. Le jour où les gabarits
// emploieront directement les noms du registre, elle disparaîtra.
var actionsFormulaire = map[string]string{
	// utilisateurs
	"create_user":     "user.create",
	"update_user":     "user.update",
	"change_password": "user.change_password",
	"delete_user":     "user.delete",
	"reset_mfa":       "user.reset_mfa",

	// Rattachement vu depuis la fiche d'un UTILISATEUR.
	//
	// Le même lien porte deux noms selon la page qui l'expose : « add_user »
	// depuis la fiche d'un groupe — on y ajoute un utilisateur — et
	// « add_group » depuis la fiche d'un utilisateur — on l'ajoute à un groupe.
	//
	// Les deux désignent la même action. L'omission de ces deux entrées aurait
	// fait refuser le rattachement depuis la fiche utilisateur avec « action de
	// formulaire inconnue », alors que la même opération fonctionnait depuis la
	// fiche groupe. C'est le genre d'écart qu'un inventaire croisé des gabarits
	// et de cette table met en évidence, et que la lecture du code seul ne
	// donne pas.
	"add_group":    "group.add_user",
	"remove_group": "group.remove_user",

	// groupes
	"create_group":             "group.create",
	"delete_group":             "group.delete",
	"add_user":                 "group.add_user",
	"remove_user":              "group.remove_user",
	"add_client":               "group.add_client",
	"remove_client":            "group.remove_client",
	"add_permission":           "group.add_permission",
	"remove_permission":        "group.remove_permission",
	"add_client_permission":    "group.add_client_permission",
	"remove_client_permission": "group.remove_client_permission",
	"add_gpo":                  "group.add_gpo",
	"remove_gpo":               "group.remove_gpo",
	"set_mfa_required":         "group.set_mfa_required",

	// machines
	"create_client": "client.create",
	"update_client": "client.update",
	"delete_client": "client.delete",

	// permissions
	"create_permission":        "permission.create",
	"delete_permission":        "permission.delete",
	"create_client_permission": "client_permission.create",
	"update_client_permission": "client_permission.update",
	"delete_client_permission": "client_permission.delete",

	// certificats
	"delete_certificate": "certificate.delete",

	// enrôlement
	"create_key": "enroll.create_key",
	"revoke_key": "enroll.revoke_key",

	// DNS
	"create_zone":   "dns.create_zone",
	"add_record":    "dns.add_record",
	"delete_record": "dns.delete_record",

	// politique de mot de passe
	"save_password_policy": "authpolicy.set_password_policy",
}

// aliasParametres traduit les noms de champs des formulaires vers ceux
// qu'attendent les actions.
//
// # Pourquoi ces alias existent
//
// Les gabarits emploient plusieurs noms pour la même chose selon la page :
// « target_group » sur le détail d'un groupe, « group » ailleurs ; « target »
// pour la cible d'une action utilisateur. Les actions, elles, ont un nom par
// concept.
//
// L'alias est appliqué SEULEMENT si le nom canonique est absent : un formulaire
// qui envoie déjà « group » n'est pas écrasé par « target_group ».
var aliasParametres = map[string]string{
	"target_group":  "group",
	"target_user":   "username",
	"target":        "username",
	"target_client": "computeur_id",
	"permission":    "permission",
	"gpo":           "gpo",
}

// Un renommage de gabarit accompagne cette table.
//
// admin_user_detail.html envoyait le NOUVEAU nom d'un compte dans un champ
// « username », tandis que la cible voyageait dans « target_user ». Les actions,
// elles, emploient « username » pour la cible — comme partout ailleurs.
//
// Ajouter un alias n'aurait pas suffi : les deux champs seraient entrés en
// conflit, et l'alias étant appliqué seulement si le nom canonique est absent,
// c'est le NOUVEAU nom qui aurait été pris pour la cible. Le compte modifié
// aurait alors été celui dont on venait de saisir le nom — donc, la plupart du
// temps, un compte qui n'existe pas.
//
// Le champ du gabarit a donc été renommé « new_username ». C'est le sens de la
// convergence : les deux façades finissent par nommer les choses pareil.

// parametresParDefaut complète les valeurs qu'une page connaît par son URL et
// que le formulaire ne renvoie pas.
//
// # Pourquoi c'est nécessaire
//
// Les pages de détail tirent leur cible de l'adresse — /admin/clients?client=X —
// et certains formulaires ne la répètent pas dans un champ caché. Le handler la
// connaît, l'action non.
//
// Sans ce complément, l'action recevrait une cible vide et rendrait « machine
// requise » alors que la page en affiche une : un message qui contredit ce que
// l'utilisateur a sous les yeux, donc incompréhensible.
func parametresParDefaut(p action.Params, defauts action.Params) action.Params {
	for nom, valeur := range defauts {
		if valeur == "" {
			continue
		}
		// Ne complète que ce qui manque : un champ explicitement transmis par
		// le formulaire l'emporte sur le contexte de la page.
		if existant, present := p[nom]; !present || strings.TrimSpace(existant) == "" {
			p[nom] = valeur
		}
	}
	return p
}

// ExecuterActionFormulaireAvec applique une action en complétant les paramètres
// avec le contexte de la page.
func ExecuterActionFormulaireAvec(r *http.Request, username string, groupIDs []int,
	defauts action.Params) (res action.Resultat, traite bool, err error) {

	if err := r.ParseForm(); err != nil {
		return action.Resultat{}, true, fmt.Errorf("formulaire illisible : %w", err)
	}
	nomFormulaire := strings.TrimSpace(r.FormValue("action"))
	if nomFormulaire == "" {
		return action.Resultat{}, false, nil
	}
	nomAction, connue := actionsFormulaire[nomFormulaire]
	if !connue {
		return action.Resultat{}, true, fmt.Errorf("%w : %q", ErrActionInconnue, nomFormulaire)
	}

	p := parametresParDefaut(parametresDepuisRequete(r), defauts)
	res, err = action.Executer(nomAction,
		action.Appelant{Username: username, GroupIDs: groupIDs}, p)
	return res, true, err
}

// ErrActionInconnue signale un « action » qui ne correspond à rien.
var ErrActionInconnue = errors.New("action de formulaire inconnue")

// parametresDepuisRequete recopie tous les champs du formulaire.
//
// TOUS, et non une liste choisie : une liste demanderait d'être tenue à jour à
// chaque champ ajouté à un gabarit, et l'oubli se manifesterait par un paramètre
// silencieusement absent — donc par une action qui s'exécute avec une valeur
// vide au lieu d'échouer.
//
// Les actions ignorent ce qu'elles ne connaissent pas ; l'excès est sans
// conséquence, le manque non.
func parametresDepuisRequete(r *http.Request) action.Params {
	p := action.Params{}
	for nom, valeurs := range r.Form {
		if len(valeurs) == 0 {
			continue
		}
		// La première valeur. Un champ répété — deux cases du même nom — n'a
		// pas de sens dans ces formulaires, et prendre la dernière ferait
		// dépendre le résultat de l'ordre du navigateur.
		p[nom] = valeurs[0]
	}

	for source, canonique := range aliasParametres {
		if _, deja := p[canonique]; deja {
			continue
		}
		if v, present := p[source]; present {
			p[canonique] = v
		}
	}
	return p
}

// ExecuterActionFormulaire traite le champ « action » d'une requête POST.
//
// Rend :
//
//	traite = false  aucun champ « action » : la requête n'en portait pas
//	err != nil      action inconnue, droit refusé, ou échec métier
//	res             le résultat, dont le message à afficher
//
// # Pourquoi l'appelant reçoit l'erreur plutôt qu'une page d'erreur
//
// Les pages d'administration affichent le message DANS la page, à côté du
// formulaire, et continuent de rendre le reste. Écrire directement une réponse
// HTTP ici priverait l'utilisateur du contexte au moment précis où il en a
// besoin — il verrait « Permission refusée » sur une page vide, sans la liste
// qu'il consultait.
func ExecuterActionFormulaire(r *http.Request, username string, groupIDs []int) (res action.Resultat, traite bool, err error) {
	if err := r.ParseForm(); err != nil {
		return action.Resultat{}, true, fmt.Errorf("formulaire illisible : %w", err)
	}

	nomFormulaire := strings.TrimSpace(r.FormValue("action"))
	if nomFormulaire == "" {
		return action.Resultat{}, false, nil
	}

	nomAction, connue := actionsFormulaire[nomFormulaire]
	if !connue {
		// Refus et non exécution. C'est le renversement par rapport à
		// l'ancien code : là-bas, un nom absent de la table laissait la clé
		// RBAC vide et l'action passait sans contrôle.
		return action.Resultat{}, true, fmt.Errorf("%w : %q", ErrActionInconnue, nomFormulaire)
	}

	appelant := action.Appelant{Username: username, GroupIDs: groupIDs}
	res, err = action.Executer(nomAction, appelant, parametresDepuisRequete(r))
	return res, true, err
}

// MessageDActionPourAffichage rend le texte à montrer dans la page.
//
// Les erreurs de droit sont distinguées des erreurs métier : les premières
// méritent le mot « refusée », que les scripts d'intégration reconnaissent et
// qu'un administrateur cherche des yeux.
func MessageDActionPourAffichage(res action.Resultat, err error) string {
	if err == nil {
		return res.Message
	}

	var refus *action.ErrRefusee
	if errors.As(err, &refus) {
		return "Permission refusée : " + refus.Motif
	}

	var inconnue *action.ErrInconnue
	if errors.As(err, &inconnue) {
		// Le cas d'un gabarit qui a pris de l'avance sur le registre. Le
		// message le dit plutôt que de laisser croire à un problème de droits.
		return "Action inconnue du serveur : " + inconnue.Nom +
			". Le formulaire et le serveur ne sont pas de la même version."
	}

	if errors.Is(err, ErrActionInconnue) {
		return err.Error()
	}

	return err.Error()
}

// ActionsDeFormulaireConnues rend la liste triée, pour les tests et l'aide.
func ActionsDeFormulaireConnues() []string {
	out := make([]string, 0, len(actionsFormulaire))
	for k := range actionsFormulaire {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ActionDuRegistrePour rend le nom d'action correspondant à un champ de
// formulaire.
func ActionDuRegistrePour(nomFormulaire string) (string, bool) {
	n, ok := actionsFormulaire[nomFormulaire]
	return n, ok
}
