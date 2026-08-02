package webserveur

import (
	"fmt"

	"vaultaire/core/logs"
	"vaultaire/core/permission"
	"vaultaire/core/storage"
)

// Filtrage des listes par domaine.
//
// POURQUOI CE FICHIER EXISTE. Les pages d'administration exigeaient autrefois le
// droit GLOBAL pour s'ouvrir : la question du périmètre ne se posait donc pas,
// puisque seul un administrateur global entrait. Depuis que l'ouverture d'une
// page ne demande plus que le droit sur au moins un domaine — sans quoi la
// délégation était décorative en web alors qu'elle fonctionnait en CLI — la
// question se pose, et elle était restée sans réponse : un délégué de
// compta.example.fr ouvrait /admin/users et voyait l'annuaire entier.
//
// Les ÉCRITURES étaient déjà contrôlées entité par entité. C'est la LECTURE qui
// manquait : il voyait sans pouvoir agir, ce qui reste une divulgation que le
// modèle de délégation existe pour empêcher.
//
// COÛT ASSUMÉ. Résoudre le domaine d'une entité demande une requête, et une
// liste de N entités en demande donc N. Le cache ci-dessous les dédoublonne à
// l'échelle d'une requête HTTP, ce qui suffit tant qu'un domaine porte des
// dizaines d'entités et non des milliers. Si un jour ça pèse, la vraie réponse
// est de filtrer en SQL, pas de retirer le filtre.

// domainScope porte le périmètre autorisé et un cache de résolution.
type domainScope struct {
	allowed permission.AllowedDomains
	cache   map[string][]string
}

// newDomainScope calcule le périmètre d'une action pour un jeu de groupes.
func newDomainScope(groupIDs []int, action string) *domainScope {
	return &domainScope{
		allowed: permission.DomainsWhereAllowed(groupIDs, action),
		cache:   make(map[string][]string),
	}
}

// unrestricted dit si le périmètre couvre tout : le filtrage est alors inutile.
func (s *domainScope) unrestricted() bool { return s.allowed.Global }

// allowsAny dit si au moins un des domaines fournis est dans le périmètre.
//
// « au moins un » et non « tous » : il s'agit de décider si l'entité est
// VISIBLE, pas si elle est modifiable. Un compte présent dans un domaine que
// j'administre m'est légitimement visible, même s'il appartient aussi à un
// domaine qui m'échappe — et c'est justement ce qui doit m'empêcher d'agir
// dessus, ce que CheckPermissionsAllDomains vérifie de son côté.
func (s *domainScope) allowsAny(domains []string) bool {
	if s.allowed.Global {
		return true
	}
	for _, d := range domains {
		if s.allowed.Allows(d) {
			return true
		}
	}
	return false
}

// domainsOfUser retourne les domaines d'un utilisateur, avec cache.
func (s *domainScope) domainsOfUser(username string) []string {
	key := "u:" + username
	if cached, ok := s.cache[key]; ok {
		return cached
	}
	domains, err := permission.GetDomainListFromUsername(username)
	if err != nil {
		// Domaine inconnu : l'entité est masquée. Une liste filtrée ne doit pas
		// laisser passer ce qu'elle n'a pas su classer.
		logs.Write_Log("DEBUG", "webadmin: domaines de "+username+" illisibles, entrée masquée")
		domains = nil
	}
	s.cache[key] = domains
	return domains
}

// domainsOfClient retourne les domaines d'une machine, avec cache.
func (s *domainScope) domainsOfClient(computeurID string) []string {
	key := "c:" + computeurID
	if cached, ok := s.cache[key]; ok {
		return cached
	}
	domains, err := permission.GetDomainsFromClientByComputerID(computeurID)
	if err != nil {
		domains = nil
	}
	s.cache[key] = domains
	return domains
}

// domainsOfPermission retourne les domaines d'une permission utilisateur.
func (s *domainScope) domainsOfPermission(name string) []string {
	key := "p:" + name
	if cached, ok := s.cache[key]; ok {
		return cached
	}
	domains, err := permission.GetDomainslistFromUserpermission(name)
	if err != nil {
		domains = nil
	}
	s.cache[key] = domains
	return domains
}

// filterUsers ne garde que les utilisateurs visibles.
func filterUsers(scope *domainScope, users []storage.GetUsers) []storage.GetUsers {
	if scope.unrestricted() {
		return users
	}
	out := make([]storage.GetUsers, 0, len(users))
	for _, u := range users {
		if scope.allowsAny(scope.domainsOfUser(u.Username)) {
			out = append(out, u)
		}
	}
	return out
}

// filterGroups ne garde que les groupes visibles.
//
// Le seul cas simple : GroupDetails porte déjà son domaine, aucune résolution
// n'est nécessaire.
func filterGroups(scope *domainScope, groups []storage.GroupDetails) []storage.GroupDetails {
	if scope.unrestricted() {
		return groups
	}
	out := make([]storage.GroupDetails, 0, len(groups))
	for _, g := range groups {
		if scope.allowed.Allows(g.DomainName) {
			out = append(out, g)
		}
	}
	return out
}

// filterClients ne garde que les machines visibles.
func filterClients(scope *domainScope, clients []storage.GetClientsByPermission) []storage.GetClientsByPermission {
	if scope.unrestricted() {
		return clients
	}
	out := make([]storage.GetClientsByPermission, 0, len(clients))
	for _, c := range clients {
		if scope.allowsAny(scope.domainsOfClient(c.ComputeurID)) {
			out = append(out, c)
		}
	}
	return out
}

// filterUserPermissions ne garde que les permissions visibles.
func filterUserPermissions(scope *domainScope, perms []storage.UserPermission) []storage.UserPermission {
	if scope.unrestricted() {
		return perms
	}
	out := make([]storage.UserPermission, 0, len(perms))
	for _, p := range perms {
		if scope.allowsAny(scope.domainsOfPermission(p.Name)) {
			out = append(out, p)
		}
	}
	return out
}

// logScopeFiltering trace une réduction de liste.
//
// Journalisé pour que la différence entre « il n'y a rien » et « vous n'avez pas
// le droit de voir » reste explicable sans lire le code : un administrateur
// délégué qui trouve sa page vide doit pouvoir obtenir une réponse.
func logScopeFiltering(username, what string, before, after int) {
	if before == after {
		return
	}
	logs.Write_Log("DEBUG", fmt.Sprintf(
		"webadmin: %s — %d %s sur %d masqué(s) hors du périmètre de %s",
		what, before-after, what, before, username))
}
