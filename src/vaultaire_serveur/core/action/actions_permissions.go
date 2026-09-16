package action

import (
	"fmt"
	"strings"

	"vaultaire/core/database"
	dbpermission "vaultaire/core/database/db_permission"
	"vaultaire/core/logs"
)

// Accès à la base, isolés derrière des variables.
//
// Même motif que pour les certificats et les machines : les tests de MESSAGE
// appellent ces actions directement alors qu'ils ne mesurent qu'une chaîne.
// Sans substitution, ils exigent une base vivante — et paniquent sur un *sql.DB
// nul quand elle manque, ce qui emporte le binaire de test entier au lieu du
// seul contrôle concerné.
var (
	creerPermUtilAdmin       = dbpermission.CreateUserPermission
	creerPermUtilDefaut      = dbpermission.CreateUserPermissionDefault
	creerPermClientEnBase    = dbpermission.CreateClientPermission
	modifierPermClientEnBase = dbpermission.Command_UPDATE_ClientPermission
)

// Actions sur les permissions.
//
// # Pourquoi ce fichier demande plus d'attention que les autres
//
// Les permissions décident de ce que tout le monde peut faire. Une action qui
// en crée ou en modifie une agit donc sur le mécanisme de contrôle lui-même, et
// non sur une donnée ordinaire.
//
// Deux réglages en particulier accordent des privilèges d'un coup :
//
//   - `web_admin` sur une permission utilisateur ouvre l'interface
//     d'administration ;
//   - `is_admin` sur une permission client donne les droits d'administration à
//     toutes les machines du groupe qui la porte.
//
// # Un point qui reste ouvert
//
// Les deux s'obtiennent avec « write:create:permission », c'est-à-dire le droit
// de créer une permission ORDINAIRE. Quelqu'un qui détient ce droit et
// « write:add:permission » peut donc créer une permission web_admin, se
// l'attribuer via un groupe, et devenir administrateur de l'interface.
//
// Ce comportement est CONSERVÉ ici : le modifier changerait ce que peuvent
// faire des délégations existantes, et ce n'est pas une décision à prendre au
// détour d'un portage. Il est journalisé en SECURITY, comme il l'était déjà
// côté web, et signalé pour arbitrage.
//
// La sortie, le jour où elle sera souhaitée : une clé distincte — par exemple
// « write:create:permission:admin » — exigée lorsque l'un de ces deux drapeaux
// est demandé.

// EnregistrerActionsPermission ajoute les actions permission au registre.
func EnregistrerActionsPermission(r *Registre) {
	r.MustEnregistrer(Definition{
		Nom:      "permission.create",
		CleRBAC:  "write:create:permission",
		Portee:   PorteeGlobale,
		Resume:   "crée une permission utilisateur",
		Executer: creerPermissionUtilisateur,
	})

	r.MustEnregistrer(Definition{
		Nom:      "permission.delete",
		CleRBAC:  "write:delete:permission",
		Portee:   porteePermissionUtilisateur,
		Resume:   "supprime une permission utilisateur",
		Executer: supprimerPermissionUtilisateur,
	})

	r.MustEnregistrer(Definition{
		Nom:      "client_permission.create",
		CleRBAC:  "write:create:permission",
		Portee:   PorteeGlobale,
		Resume:   "crée une permission client",
		Executer: creerPermissionClient,
	})

	r.MustEnregistrer(Definition{
		Nom:      "client_permission.update",
		CleRBAC:  "write:update:permission",
		Portee:   porteePermissionClient,
		Resume:   "accorde ou retire l'administration à une permission client",
		Executer: modifierPermissionClient,
	})

	r.MustEnregistrer(Definition{
		Nom:      "client_permission.delete",
		CleRBAC:  "write:delete:permission",
		Portee:   porteePermissionClient,
		Resume:   "supprime une permission client",
		Executer: supprimerPermissionClient,
	})
}

// porteePermissionUtilisateur exige le droit sur les domaines de la permission.
//
// Une permission porte des domaines : la modifier revient à agir sur eux. Un
// délégué de Paris ne doit pas pouvoir supprimer une permission qui accorde des
// droits à Lyon.
func porteePermissionUtilisateur(p Params) ([]string, error) {
	return domainesOuGlobal(permissionDomainesUtilisateur(p.Get("permission_name")))
}

func porteePermissionClient(p Params) ([]string, error) {
	return domainesOuGlobal(permissionDomainesClient(p.Get("permission_name")))
}

// creerPermissionUtilisateur crée une permission, éventuellement admin web.
func creerPermissionUtilisateur(a Appelant, p Params) (Resultat, error) {
	nom := p.Get("name")
	description := p.Get("description")

	if nom == "" {
		return Resultat{}, fmt.Errorf("nom de la permission requis")
	}
	if strings.ContainsAny(nom, ":\n\r") {
		// Le « : » sépare les composants d'une clé d'action
		// (catégorie:action:objet). Un nom de permission qui en contient
		// rendrait les journaux et les comparaisons ambigus.
		return Resultat{}, fmt.Errorf("nom de permission %q invalide : le caractère « : » est réservé", nom)
	}

	adminWeb, err := booleen(p.Get("web_admin"))
	if err != nil {
		return Resultat{}, fmt.Errorf("valeur web_admin invalide : %w", err)
	}

	// Le raccourci venait du web. Une permission naissait avec toutes ses
	// actions à « nil » : il fallait la créer, ouvrir son détail, puis régler
	// web_admin pour qu'elle serve à quelque chose. La ligne de commande
	// n'offrait pas ce raccourci ; il est repris ici pour les deux.
	if adminWeb {
		_, err = creerPermUtilAdmin(
			database.GetDatabase(), nom, description, "nil", "all", "nil", "nil", "nil")
	} else {
		_, err = creerPermUtilDefaut(database.GetDatabase(), nom, description)
	}
	if err != nil {
		return Resultat{}, fmt.Errorf("erreur lors de la création de la permission : %w", err)
	}

	if adminWeb {
		// Trace en SECURITY : cette permission ouvre l'interface
		// d'administration. Savoir qui l'a créée, et quand, est ce qu'on
		// cherchera d'abord si un accès inattendu apparaît.
		logs.Write_Log("SECURITY", fmt.Sprintf(
			"permission utilisateur %q créée avec web_admin par %s", nom, a.Username))
	}

	// Le compte rendu dit ce qui a été enregistré ET la suite à donner.
	//
	// Il annonçait « Ouvrez son détail pour régler les actions RBAC », ce qui ne
	// désigne rien pour qui vient de taper une commande : « son détail » est une
	// page du portail. Une permission naît SANS AUCUN droit — elle n'autorise
	// donc rien tant qu'on ne l'a pas réglée — et la commande qui la règle
	// n'était nommée nulle part.
	message := fmt.Sprintf("Permission %s créée", nom)
	if description != "" {
		message += fmt.Sprintf(" (%s)", description)
	}
	message += ".\n"

	if adminWeb {
		message += "Elle ouvre l'ADMINISTRATION WEB : tout groupe qui la portera pourra " +
			"administrer Vaultaire.\n"
	} else {
		message += "Elle n'accorde encore AUCUN droit.\n"
	}
	message += "  régler un droit  : update -pu " + nom + " <clé> nil|all|-a|-r [propagation] [domaine]\n" +
		"  consulter        : get -p -u " + nom + "\n" +
		"  rattacher        : add -gu <groupe> -p " + nom

	return Resultat{
		Message: message,
		Donnees: map[string]any{"name": nom, "web_admin": adminWeb, "description": description},
	}, nil
}

func supprimerPermissionUtilisateur(_ Appelant, p Params) (Resultat, error) {
	nom := p.Get("permission_name")
	if nom == "" {
		return Resultat{}, fmt.Errorf("nom de la permission requis")
	}
	if err := dbpermission.Command_DELETE_UserPermissionByName(database.GetDatabase(), nom); err != nil {
		return Resultat{}, fmt.Errorf("erreur lors de la suppression de la permission %q : %w", nom, err)
	}
	return Resultat{Message: fmt.Sprintf("Permission %s supprimée.", nom)}, nil
}

// creerPermissionClient crée une permission pour les machines.
func creerPermissionClient(a Appelant, p Params) (Resultat, error) {
	nom := p.Get("name")
	if nom == "" {
		return Resultat{}, fmt.Errorf("nom de la permission client requis")
	}
	if strings.ContainsAny(nom, ":\n\r") {
		return Resultat{}, fmt.Errorf("nom de permission %q invalide : le caractère « : » est réservé", nom)
	}

	estAdmin, err := booleen(p.Get("is_admin"))
	if err != nil {
		return Resultat{}, fmt.Errorf("valeur is_admin invalide : %w", err)
	}

	if _, err := creerPermClientEnBase(database.GetDatabase(), nom, estAdmin); err != nil {
		return Resultat{}, fmt.Errorf("erreur lors de la création de la permission client : %w", err)
	}

	if estAdmin {
		// Une permission client admin donne les droits d'administration aux
		// MACHINES du groupe qui la porte — pas à une personne. La trace
		// importe d'autant plus qu'aucun humain n'est identifié derrière ce
		// privilège une fois qu'il s'exerce.
		logs.Write_Log("SECURITY", fmt.Sprintf(
			"permission client ADMIN %q créée par %s", nom, a.Username))
	}

	message := fmt.Sprintf("Permission client %s créée.\n", nom)
	if estAdmin {
		message = fmt.Sprintf(
			"Permission client %s créée en ADMIN : les machines du groupe qui la portera "+
				"disposeront des droits d'administration.\n", nom)
	}
	// Comme pour les permissions utilisateur : une permission qui n'est
	// rattachée à aucun groupe ne s'applique à personne, et la commande qui
	// l'attache n'était nommée nulle part.
	message += "  consulter  : get -p -c " + nom + "\n" +
		"  rattacher  : add -gc <groupe> -p " + nom

	return Resultat{
		Message: message,
		Donnees: map[string]any{"name": nom, "is_admin": estAdmin},
	}, nil
}

// modifierPermissionClient accorde ou retire l'administration.
func modifierPermissionClient(a Appelant, p Params) (Resultat, error) {
	nom := p.Get("permission_name")
	if nom == "" {
		return Resultat{}, fmt.Errorf("nom de la permission client requis")
	}

	estAdmin, err := booleen(p.Get("is_admin"))
	if err != nil {
		return Resultat{}, fmt.Errorf("valeur is_admin invalide : %w", err)
	}

	if err := modifierPermClientEnBase(database.GetDatabase(), nom, estAdmin); err != nil {
		return Resultat{}, fmt.Errorf("erreur lors de la mise à jour de la permission client %q : %w", nom, err)
	}

	// Tracé dans les DEUX sens. L'ancienne version journalisait aussi le
	// retrait, et c'est juste : perdre un privilège explique des refus qui
	// paraîtraient autrement inexplicables, et la trace est ce qui permet de
	// relier les deux.
	logs.Write_Log("SECURITY", fmt.Sprintf(
		"permission client %q passée à admin=%t par %s", nom, estAdmin, a.Username))

	if estAdmin {
		return Resultat{Message: fmt.Sprintf(
			"Permission client %s passée en ADMIN. Les machines du groupe qui la porte "+
				"disposent désormais des droits d'administration.", nom)}, nil
	}
	return Resultat{Message: fmt.Sprintf(
		"Permission client %s : administration retirée.", nom)}, nil
}

func supprimerPermissionClient(_ Appelant, p Params) (Resultat, error) {
	nom := p.Get("permission_name")
	if nom == "" {
		return Resultat{}, fmt.Errorf("nom de la permission client requis")
	}
	if err := dbpermission.Command_DELETE_ClientPermissionByName(database.GetDatabase(), nom); err != nil {
		return Resultat{}, fmt.Errorf("erreur lors de la suppression de la permission client %q : %w", nom, err)
	}
	return Resultat{Message: fmt.Sprintf("Permission client %s supprimée.", nom)}, nil
}
