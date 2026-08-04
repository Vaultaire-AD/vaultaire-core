package webserveur

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	dbclients "vaultaire/core/database/db_clients"
	dbgroups "vaultaire/core/database/db_groups"
	dbusers "vaultaire/core/database/db_users"

	"vaultaire/core/database"
	dbpermission "vaultaire/core/database/db_permission"
	"vaultaire/core/logs"
)

// SearchResult represents one search hit for the global search API.
type SearchResult struct {
	Type string `json:"type"` // "user", "group", "client", "permission"
	ID   string `json:"id"`   // username, group name, computeur_id, permission name
	Name string `json:"name"`
	URL  string `json:"url"`
}

// AdminSearchAPIHandler serves GET /admin/api/search?q=... (JSON: users, groups, clients, permissions).
// Access: web_admin + legacy action "search" (same as search in permission model).
func AdminSearchAPIHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username, groupIDs, ok := requireWebAdminWithGroupIDs(w, r)
	if !ok {
		return
	}
	if !checkWebAdminRBAC(w, r, groupIDs, "search") {
		return
	}

	// La recherche interroge les quatre familles d'un coup : sans filtrage, elle
	// devenait le chemin le plus court pour énumérer tout l'annuaire depuis une
	// simple barre de recherche, y compris pour un administrateur délégué sur un
	// seul domaine.
	//
	// Le périmètre est calculé par famille et non une fois pour toutes : on peut
	// légitimement avoir le droit de lire les groupes d'un domaine sans avoir
	// celui d'en lire les comptes.
	userScope := newDomainScope(groupIDs, "read:get:user")
	groupScope := newDomainScope(groupIDs, "read:get:group")
	clientScope := newDomainScope(groupIDs, "read:get:client")
	permScope := newDomainScope(groupIDs, "read:get:permission")
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(q) < 2 {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string][]SearchResult{
			"users":       nil,
			"groups":      nil,
			"clients":     nil,
			"permissions": nil,
		})
		return
	}
	qLower := strings.ToLower(q)
	db := database.GetDatabase()

	var users []SearchResult
	allUsers, _ := dbusers.Command_GET_AllUsers(db)
	for _, u := range allUsers {
		if !userScope.allowsAny(userScope.domainsOfUser(u.Username)) {
			continue
		}
		if strings.Contains(strings.ToLower(u.Username), qLower) || strings.Contains(strings.ToLower(u.Email), qLower) {
			users = append(users, SearchResult{Type: "user", ID: u.Username, Name: u.Username, URL: "/admin/users?user=" + u.Username})
		}
	}

	var groups []SearchResult
	allGroups, _ := dbgroups.Command_GET_GroupDetails(db)
	for _, g := range allGroups {
		if !groupScope.allowsAny([]string{g.DomainName}) {
			continue
		}
		if strings.Contains(strings.ToLower(g.GroupName), qLower) || strings.Contains(strings.ToLower(g.DomainName), qLower) {
			groups = append(groups, SearchResult{Type: "group", ID: g.GroupName, Name: g.GroupName + " (" + g.DomainName + ")", URL: "/admin/groups?group=" + g.GroupName})
		}
	}

	var clients []SearchResult
	allClients, _ := dbclients.Command_GET_AllClients(db)
	for _, c := range allClients {
		if !clientScope.allowsAny(clientScope.domainsOfClient(c.ComputeurID)) {
			continue
		}
		if strings.Contains(strings.ToLower(c.ComputeurID), qLower) || strings.Contains(strings.ToLower(c.Hostname), qLower) {
			clients = append(clients, SearchResult{Type: "client", ID: c.ComputeurID, Name: c.Hostname + " (" + c.ComputeurID + ")", URL: "/admin/clients?client=" + c.ComputeurID})
		}
	}

	var perms []SearchResult
	allPerms, _ := dbpermission.Command_GET_AllUserPermissions(db)
	for _, p := range allPerms {
		if !permScope.allowsAny(permScope.domainsOfPermission(p.Name)) {
			continue
		}
		if strings.Contains(strings.ToLower(p.Name), qLower) || strings.Contains(strings.ToLower(p.Description), qLower) {
			perms = append(perms, SearchResult{Type: "permission", ID: p.Name, Name: p.Name, URL: "/admin/permissions?perm=" + p.Name})
		}
	}

	logs.Write_Log("DEBUG", fmt.Sprintf(
		"webadmin: recherche de %s — %d utilisateur(s), %d groupe(s), %d client(s), %d permission(s) dans son périmètre",
		username, len(users), len(groups), len(clients), len(perms)))

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string][]SearchResult{
		"users":       users,
		"groups":      groups,
		"clients":     clients,
		"permissions": perms,
	})
}
