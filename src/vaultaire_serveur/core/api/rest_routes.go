package api

import "net/http"

// Les routes REST « ressources » — TO-DO 270.
//
// # Une table, et rien d'autre
//
// Chaque route NOMME une action du registre — celle que la ligne de commande
// appelle pour le même geste. Elle n'a ni contrôle de droits, ni accès à la
// base, ni règle métier : tout cela est dans l'action, partagé avec `vlt` et le
// portail. Ajouter une route, c'est ajouter une ligne ici ; le reste (droits,
// portée, filtre des listes, journal d'audit) vient avec l'action.
//
// Les noms entre accolades sont les NOMS DES PARAMÈTRES de l'action : la valeur
// du chemin est passée telle quelle (`{username}` → `username`). Le corps JSON
// et la requête apportent les autres. Un même paramètre donné à la fois dans le
// chemin et dans le corps avec deux valeurs différentes est refusé : le corps
// ne doit pas pouvoir changer la cible que l'URL désigne.
//
// Ce qui n'a pas de route ici reste joignable par la route générique
// `/api/v1/actions/{action}` (toutes les actions du registre), et ce qui n'est
// pas encore dans le registre (`status`, `eyes`, `logs`…) par
// `POST /api/v1/command`.

// routeREST décrit une route ressource.
type routeREST struct {
	Methode string
	Chemin  string // sous /api/v1, motif net/http (« {nom} »)
	Action  string
	Statut  int // statut du succès ; 200 si zéro
	Resume  string
	Tag     string
}

var routesREST = []routeREST{
	// --- Comptes -----------------------------------------------------------
	{"GET", "/users", "user.list", 0, "liste les comptes (réduite au périmètre de l'appelant)", "users"},
	{"POST", "/users", "user.create", http.StatusCreated, "crée un compte ; « group » pour le créer dans un groupe (création déléguée), « email » pour choisir son adresse", "users"},
	{"GET", "/users/{username}", "user.get", 0, "détail d'un compte", "users"},
	{"PATCH", "/users/{username}", "user.update", 0, "modifie identifiant, prénom, nom ou adresse (new_username, firstname, lastname, email — « auto » : compte@domaine)", "users"},
	{"DELETE", "/users/{username}", "user.delete", 0, "supprime un compte et le retire du parc", "users"},
	{"PUT", "/users/{username}/password", "user.change_password", 0, "change le mot de passe (password, temporary)", "users"},
	{"DELETE", "/users/{username}/mfa", "user.reset_mfa", 0, "réinitialise le second facteur", "users"},
	{"GET", "/users/{username}/keys", "user.list_keys", 0, "clés SSH d'un compte", "users"},
	{"POST", "/users/{username}/keys", "user.add_key", http.StatusCreated, "ajoute une clé SSH (key, label)", "users"},
	{"DELETE", "/users/{username}/keys/{key_id}", "user.remove_key", 0, "retire une clé SSH", "users"},

	// --- Groupes -----------------------------------------------------------
	{"GET", "/groups", "group.list", 0, "liste les groupes", "groups"},
	{"POST", "/groups", "group.create", http.StatusCreated, "crée un groupe (group, domain)", "groups"},
	{"GET", "/groups/{group}", "group.get", 0, "détail d'un groupe", "groups"},
	{"DELETE", "/groups/{group}", "group.delete", 0, "supprime un groupe", "groups"},
	{"PUT", "/groups/{group}/mfa", "group.set_mfa_required", 0, "exige ou non le second facteur (mfa_required)", "groups"},
	{"GET", "/groups/{group}/users", "group.list_users", 0, "membres d'un groupe", "groups"},
	{"PUT", "/groups/{group}/users/{username}", "group.add_user", 0, "ajoute un compte au groupe", "groups"},
	{"DELETE", "/groups/{group}/users/{username}", "group.remove_user", 0, "retire un compte du groupe", "groups"},
	{"GET", "/groups/{group}/clients", "group.list_clients", 0, "machines d'un groupe", "groups"},
	{"PUT", "/groups/{group}/clients/{computeur_id}", "group.add_client", 0, "ajoute une machine au groupe", "groups"},
	{"DELETE", "/groups/{group}/clients/{computeur_id}", "group.remove_client", 0, "retire une machine du groupe", "groups"},
	{"PUT", "/groups/{group}/permissions/{permission}", "group.add_permission", 0, "attache une permission utilisateur", "groups"},
	{"DELETE", "/groups/{group}/permissions/{permission}", "group.remove_permission", 0, "détache une permission utilisateur", "groups"},
	{"PUT", "/groups/{group}/client-permissions/{client_permission}", "group.add_client_permission", 0, "attache une permission client", "groups"},
	{"DELETE", "/groups/{group}/client-permissions/{client_permission}", "group.remove_client_permission", 0, "détache une permission client", "groups"},
	{"PUT", "/groups/{group}/gpos/{gpo}", "group.add_gpo", 0, "lie une GPO au groupe", "groups"},
	{"DELETE", "/groups/{group}/gpos/{gpo}", "group.remove_gpo", 0, "délie une GPO du groupe", "groups"},

	// --- Domaines ----------------------------------------------------------
	{"GET", "/domains", "domain.list_tree", 0, "arborescence des domaines", "domains"},
	{"GET", "/domains/{domain}/groups", "domain.list_groups", 0, "groupes d'un domaine", "domains"},

	// --- Machines ----------------------------------------------------------
	{"GET", "/clients", "client.list", 0, "liste les machines", "clients"},
	{"POST", "/clients", "client.create", http.StatusCreated, "crée une machine (is_serveur)", "clients"},
	{"GET", "/clients/{computeur_id}", "client.get", 0, "détail d'une machine", "clients"},
	{"PATCH", "/clients/{computeur_id}", "client.update", 0, "modifie une machine", "clients"},
	{"DELETE", "/clients/{computeur_id}", "client.delete", 0, "supprime une machine", "clients"},
	{"GET", "/clients/{computeur_id}/compliance", "gpo.get_compliance", 0, "conformité GPO d'une machine", "clients"},
	{"POST", "/clients/{computeur_id}/gpo-refresh", "gpo.refresh", 0, "demande une réapplication des GPO (motif, attendre)", "clients"},

	// --- Permissions utilisateur -------------------------------------------
	{"GET", "/permissions", "permission.list", 0, "liste les permissions utilisateur", "permissions"},
	{"POST", "/permissions", "permission.create", http.StatusCreated, "crée une permission (name, web_admin, description)", "permissions"},
	{"GET", "/permissions/{permission_name}", "permission.get", 0, "détail d'une permission", "permissions"},
	{"DELETE", "/permissions/{permission_name}", "permission.delete", 0, "supprime une permission", "permissions"},
	{"PATCH", "/permissions/{permission_name}/actions", "permission.update_action", 0, "règle un droit RBAC (field, op, domain, propagation)", "permissions"},

	// --- Permissions client ------------------------------------------------
	{"GET", "/client-permissions", "client_permission.list", 0, "liste les permissions client", "permissions"},
	{"POST", "/client-permissions", "client_permission.create", http.StatusCreated, "crée une permission client (name, is_admin)", "permissions"},
	{"GET", "/client-permissions/{permission_name}", "client_permission.get", 0, "détail d'une permission client", "permissions"},
	{"PATCH", "/client-permissions/{permission_name}", "client_permission.update", 0, "modifie une permission client (is_admin)", "permissions"},
	{"DELETE", "/client-permissions/{permission_name}", "client_permission.delete", 0, "supprime une permission client", "permissions"},

	// --- GPO ---------------------------------------------------------------
	{"GET", "/gpos", "gpo.list", 0, "liste les GPO", "gpos"},
	{"POST", "/gpos", "gpo.create", http.StatusCreated, "crée une GPO (name, scope, description)", "gpos"},
	{"GET", "/gpos/compliance", "gpo.list_compliance", 0, "conformité du parc", "gpos"},
	{"GET", "/gpos/{gpo}", "gpo.get", 0, "détail d'une GPO et de ses modules", "gpos"},
	{"PATCH", "/gpos/{gpo}", "gpo.update", 0, "modifie une GPO (description, enabled)", "gpos"},
	{"DELETE", "/gpos/{gpo}", "gpo.delete", 0, "supprime une GPO", "gpos"},
	{"POST", "/gpos/{gpo}/modules", "gpo.add_module", http.StatusCreated, "ajoute un module (module_type et ses paramètres)", "gpos"},
	{"PATCH", "/gpos/{gpo}/modules/{module_id}", "gpo.update_module", 0, "modifie un module", "gpos"},
	{"DELETE", "/gpos/{gpo}/modules/{module_id}", "gpo.delete_module", 0, "retire un module", "gpos"},
}
