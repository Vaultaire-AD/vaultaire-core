package action

import (
	"fmt"

	"vaultaire/core/database"
	dbclients "vaultaire/core/database/db_clients"
	dbgpo "vaultaire/core/database/db_gpo"
	dbpermission "vaultaire/core/database/db_permission"
	"vaultaire/core/permission"
	"vaultaire/core/storage"
)

// Actions de LECTURE — machines, permissions, GPO.
//
// Suite de actions_lectures.go, qui porte les utilisateurs et les groupes.
// Séparées par fichier plutôt que par paquet : elles partagent les filtres et
// les portées, et les mélanger dans un seul fichier de six cents lignes rendrait
// l'inventaire illisible.
//
// # Deux défauts trouvés dans ce lot
//
//  1. `get -c` (liste des machines) et `get -p -u` / `get -p -c` (listes de
//     permissions) exigeaient le droit sur « * » — donc le droit GLOBAL. Un
//     délégué de paris, qui a pourtant le droit sur son domaine, se voyait
//     refuser la liste entièrement. Le web, lui, la lui montrait filtrée.
//     La façade décidait donc non seulement de ce qu'on voit, mais de si l'on
//     voit.
//
//     Corrigé par le couple habituel : portée globale mais UnDomaineSuffit, et
//     un filtre qui réduit la liste au périmètre. Le délégué obtient donc sa
//     part au lieu d'un refus.
//
//  2. `lireActionsRBAC` vivait dans commandget : la fiche d'une permission
//     montrait ses droits RBAC en ligne de commande, et pas sur le web, qui
//     reconstruisait sa propre matrice. Elle est ici, donc dans la réponse de
//     l'action, donc identique des deux côtés.

// EnregistrerActionsLectureSuite ajoute machines, permissions et GPO.
func EnregistrerActionsLectureSuite(r *Registre) {
	// --- machines ---

	r.MustEnregistrer(Definition{
		Nom:     "client.list",
		CleRBAC: "read:get:client",
		// Globale + UnDomaineSuffit : le droit sur un domaine ouvre la liste,
		// le filtre la réduit. Exiger « * » refusait tout au délégué.
		Portee:          PorteeGlobale,
		PorteeOuverte:   true,
		Filtre:          filtrerMachines,
		Resume:          "liste toutes les machines",
		Executer:        listerMachines,
	})

	r.MustEnregistrer(Definition{
		Nom:             "client.get",
		CleRBAC:         "read:get:client",
		Portee:          PorteeClient,
		UnDomaineSuffit: true,
		Resume:          "affiche la fiche d'une machine",
		Executer:        lireMachine,
	})

	// --- permissions ---

	r.MustEnregistrer(Definition{
		Nom:             "permission.list",
		CleRBAC:         "read:get:permission",
		Portee:          PorteeGlobale,
		PorteeOuverte:   true,
		Filtre:          filtrerPermissionsUtilisateur,
		Resume:          "liste les permissions utilisateur",
		Executer:        listerPermissionsUtilisateur,
	})

	r.MustEnregistrer(Definition{
		Nom:             "permission.get",
		CleRBAC:         "read:get:permission",
		Portee:          porteePermissionUtilisateur,
		UnDomaineSuffit: true,
		Resume:          "affiche une permission utilisateur et ses actions RBAC",
		Executer:        lirePermissionUtilisateur,
	})

	r.MustEnregistrer(Definition{
		Nom:             "client_permission.list",
		CleRBAC:         "read:get:permission",
		Portee:          PorteeGlobale,
		PorteeOuverte:   true,
		Filtre:          filtrerPermissionsClient,
		Resume:          "liste les permissions client",
		Executer:        listerPermissionsClient,
	})

	r.MustEnregistrer(Definition{
		Nom:             "client_permission.get",
		CleRBAC:         "read:get:permission",
		Portee:          porteePermissionClient,
		UnDomaineSuffit: true,
		Resume:          "affiche une permission client",
		Executer:        lirePermissionClient,
	})

	// --- GPO ---

	r.MustEnregistrer(Definition{
		Nom:             "gpo.list",
		CleRBAC:         "read:get:gpo",
		Portee:          PorteeGlobale,
		PorteeOuverte:   true,
		Filtre:          filtrerGPO,
		Resume:          "liste les GPO",
		Executer:        listerGPO,
	})

	r.MustEnregistrer(Definition{
		Nom:             "gpo.get",
		CleRBAC:         "read:get:gpo",
		Portee:          porteeGPO,
		UnDomaineSuffit: true,
		Resume:          "affiche le détail d'une GPO",
		Executer:        lireGPO,
	})
}

// porteeGPO exige le droit sur les domaines des groupes liés à la GPO.
//
// Une GPO sans groupe ne couvre aucun domaine. domainesOuGlobal exige alors le
// droit global : sans cela, une GPO non rattachée serait l'objet le plus
// accessible du système, puisque la liste vide de CheckPermissions n'a rien à
// vérifier.
func porteeGPO(p Params) ([]string, error) {
	return domainesOuGlobal(permission.GetDomainslistFromGPO(p.Get("gpo")))
}

// --- filtres -----------------------------------------------------------------

func filtrerMachines(donnees any, perim Perimetre) (any, int) {
	clients, ok := donnees.([]storage.GetClientsByPermission)
	if !ok {
		return donnees, 0
	}
	garde := make([]storage.GetClientsByPermission, 0, len(clients))
	for _, c := range clients {
		if perim.AutoriseUnDes(perim.DomainesDe(EntiteClient, c.ComputeurID)) {
			garde = append(garde, c)
		}
	}
	return garde, len(clients) - len(garde)
}

func filtrerPermissionsUtilisateur(donnees any, perim Perimetre) (any, int) {
	perms, ok := donnees.([]storage.UserPermission)
	if !ok {
		return donnees, 0
	}
	garde := make([]storage.UserPermission, 0, len(perms))
	for _, p := range perms {
		if perim.AutoriseUnDes(perim.DomainesDe(EntitePermission, p.Name)) {
			garde = append(garde, p)
		}
	}
	return garde, len(perms) - len(garde)
}

func filtrerPermissionsClient(donnees any, perim Perimetre) (any, int) {
	perms, ok := donnees.([]storage.ClientPermission)
	if !ok {
		return donnees, 0
	}
	garde := make([]storage.ClientPermission, 0, len(perms))
	for _, p := range perms {
		if perim.AutoriseUnDes(perim.DomainesDe(EntitePermissionClient, p.Name)) {
			garde = append(garde, p)
		}
	}
	return garde, len(perms) - len(garde)
}

func filtrerGPO(donnees any, perim Perimetre) (any, int) {
	policies, ok := donnees.([]dbgpo.PolicySummary)
	if !ok {
		return donnees, 0
	}
	garde := make([]dbgpo.PolicySummary, 0, len(policies))
	for _, p := range policies {
		if perim.AutoriseUnDes(perim.DomainesDe(EntiteGPO, p.Name)) {
			garde = append(garde, p)
		}
	}
	return garde, len(policies) - len(garde)
}

// --- machines ----------------------------------------------------------------

func listerMachines(_ Appelant, _ Params) (Resultat, error) {
	clients, err := dbclients.Command_GET_AllClients(database.GetDatabase())
	if err != nil {
		return Resultat{}, fmt.Errorf("lecture des machines : %w", err)
	}
	return Resultat{
		Message: fmt.Sprintf("%d machine(s).", len(clients)),
		Donnees: clients,
	}, nil
}

func lireMachine(_ Appelant, p Params) (Resultat, error) {
	id := p.Get("computeur_id")
	if id == "" {
		return Resultat{}, fmt.Errorf("identifiant de machine requis")
	}
	client, err := dbclients.Command_GET_ClientByComputeurID(database.GetDatabase(), id)
	if err != nil {
		return Resultat{}, fmt.Errorf("machine %q introuvable : %w", id, err)
	}
	return Resultat{Message: "Machine " + id + ".", Donnees: client}, nil
}

// --- permissions -------------------------------------------------------------

func listerPermissionsUtilisateur(_ Appelant, _ Params) (Resultat, error) {
	perms, err := dbpermission.Command_GET_AllUserPermissions(database.GetDatabase())
	if err != nil {
		return Resultat{}, fmt.Errorf("lecture des permissions utilisateur : %w", err)
	}
	return Resultat{
		Message: fmt.Sprintf("%d permission(s) utilisateur.", len(perms)),
		Donnees: perms,
	}, nil
}

func listerPermissionsClient(_ Appelant, _ Params) (Resultat, error) {
	perms, err := dbpermission.Command_GET_AllClientPermissions(database.GetDatabase())
	if err != nil {
		return Resultat{}, fmt.Errorf("lecture des permissions client : %w", err)
	}
	return Resultat{
		Message: fmt.Sprintf("%d permission(s) client.", len(perms)),
		Donnees: perms,
	}, nil
}

// PermissionAvecActions porte une permission et ses droits RBAC.
//
// Les deux vont ensemble : une permission sans ses actions ne dit pas ce
// qu'elle accorde, et c'est précisément la question qu'on pose en l'affichant.
type PermissionAvecActions struct {
	Permission storage.UserPermission

	// Actions est nil si la base n'a pas répondu — distinct d'une liste vide,
	// qui voudrait dire « aucun droit ». L'affichage doit pouvoir dire « non
	// lu » plutôt que « n'accorde rien ».
	Actions []ActionRBAC
}

// ActionRBAC est une clé d'action et sa valeur pour une permission.
type ActionRBAC struct {
	Cle    string
	Valeur string
}

func lirePermissionUtilisateur(_ Appelant, p Params) (Resultat, error) {
	nom := p.Get("permission_name")
	if nom == "" {
		return Resultat{}, fmt.Errorf("nom de permission requis")
	}
	perm, err := dbpermission.Command_GET_UserPermissionByName(database.GetDatabase(), nom)
	if err != nil {
		return Resultat{}, fmt.Errorf("permission %q introuvable : %w", nom, err)
	}
	return Resultat{
		Message: "Permission " + nom + ".",
		Donnees: PermissionAvecActions{
			Permission: *perm,
			Actions:    LireActionsRBAC(int64(perm.ID)),
		},
	}, nil
}

func lirePermissionClient(_ Appelant, p Params) (Resultat, error) {
	nom := p.Get("permission_name")
	if nom == "" {
		return Resultat{}, fmt.Errorf("nom de permission requis")
	}
	perm, err := dbpermission.Command_GET_ClientPermissionByName(database.GetDatabase(), nom)
	if err != nil {
		return Resultat{}, fmt.Errorf("permission client %q introuvable : %w", nom, err)
	}
	return Resultat{Message: "Permission client " + nom + ".", Donnees: perm}, nil
}

// LireActionsRBAC rassemble les droits d'une permission utilisateur.
//
// # Pourquoi lire TOUTES les clés plutôt que celles présentes en base
//
// La table user_permission_action ne contient que les actions réglées au moins
// une fois. Une permission fraîchement créée y a zéro ligne — ce qui ne veut
// pas dire qu'elle accorde tout, mais qu'elle n'accorde rien.
//
// Ne lister que les lignes présentes donnerait une fiche vide, impossible à
// distinguer d'un défaut de lecture. On interroge donc chaque clé connue, et
// l'absence est rendue explicitement.
//
// # Pourquoi elle a quitté commandget
//
// Elle y était seule : la fiche d'une permission montrait ses droits RBAC en
// ligne de commande, tandis que le web reconstruisait sa propre matrice. Deux
// lectures, deux instants, deux réponses possibles à la même question.
//
// Exportée parce que l'interface web s'en sert pour bâtir sa matrice sur la
// même source.
//
// # Sur le coût
//
// Une requête par clé, soit une trentaine. Acceptable pour une consultation ;
// à revoir si cette fonction devait servir dans une boucle, ce qui n'est pas
// le cas.
func LireActionsRBAC(permissionID int64) []ActionRBAC {
	db := database.GetDatabase()
	if db == nil {
		// nil et non une liste vide : l'affichage distingue les deux, et dire
		// « base indisponible » vaut mieux qu'afficher une permission qui
		// paraîtrait ne rien accorder.
		return nil
	}

	cles := permission.AllRBACActionKeys()
	cles = append(cles, permission.SpecialActionKeys()...)

	out := make([]ActionRBAC, 0, len(cles))
	for _, cle := range cles {
		valeur, err := dbpermission.Command_GET_UserPermissionAction(db, permissionID, cle)
		if err != nil {
			// Une clé jamais réglée n'a pas de ligne : l'erreur signifie
			// « absente », donc « refusée ». La traiter comme un échec de
			// lecture ferait échouer la fiche entière sur le cas le plus
			// courant.
			valeur = "nil"
		}
		out = append(out, ActionRBAC{Cle: cle, Valeur: valeur})
	}
	return out
}

// --- GPO ---------------------------------------------------------------------

func listerGPO(_ Appelant, _ Params) (Resultat, error) {
	policies, err := dbgpo.GetAllPolicies(database.GetDatabase())
	if err != nil {
		return Resultat{}, fmt.Errorf("lecture des GPO : %w", err)
	}
	return Resultat{
		Message: fmt.Sprintf("%d GPO.", len(policies)),
		Donnees: policies,
	}, nil
}

func lireGPO(_ Appelant, p Params) (Resultat, error) {
	nom := p.Get("gpo")
	if nom == "" {
		return Resultat{}, fmt.Errorf("nom de GPO requis")
	}
	policy, err := dbgpo.GetPolicyByName(database.GetDatabase(), nom)
	if err != nil {
		return Resultat{}, fmt.Errorf("GPO %q introuvable : %w", nom, err)
	}
	return Resultat{Message: "GPO " + nom + ".", Donnees: policy}, nil
}
