package webserveur

import (
	"vaultaire/serveur/database"
	dbperm "vaultaire/serveur/database/db_permission"
	"encoding/json"
	"net/http"
	"strings"
)

// SearchResult represents one search hit for the global search API.
type SearchResult struct {
	Type string `json:"type"` // "user", "group", "client", "permission"
	ID   string `json:"id"`   // username, group name, computeur_id, permission name
	Name string `json:"name"`
	URL  string `json:"url"`
}

// AdminSearchAPIHandler serves GET /admin/api/search?q=... (JSON: users, groups, clients, permissions).
func AdminSearchAPIHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_, ok := requireWebAdmin(w, r)
	if !ok {
		return
	}
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
	allUsers, _ := database.Command_GET_AllUsers(db)
	for _, u := range allUsers {
		if strings.Contains(strings.ToLower(u.Username), qLower) || strings.Contains(strings.ToLower(u.Email), qLower) {
			users = append(users, SearchResult{Type: "user", ID: u.Username, Name: u.Username, URL: "/admin/users?user=" + u.Username})
		}
	}

	var groups []SearchResult
	allGroups, _ := database.Command_GET_GroupDetails(db)
	for _, g := range allGroups {
		if strings.Contains(strings.ToLower(g.GroupName), qLower) || strings.Contains(strings.ToLower(g.DomainName), qLower) {
			groups = append(groups, SearchResult{Type: "group", ID: g.GroupName, Name: g.GroupName + " (" + g.DomainName + ")", URL: "/admin/groups?group=" + g.GroupName})
		}
	}

	var clients []SearchResult
	allClients, _ := database.Command_GET_AllClients(db)
	for _, c := range allClients {
		if strings.Contains(strings.ToLower(c.ComputeurID), qLower) || strings.Contains(strings.ToLower(c.Hostname), qLower) {
			clients = append(clients, SearchResult{Type: "client", ID: c.ComputeurID, Name: c.Hostname + " (" + c.ComputeurID + ")", URL: "/admin/clients?client=" + c.ComputeurID})
		}
	}

	var perms []SearchResult
	allPerms, _ := dbperm.Command_GET_AllUserPermissions(db)
	for _, p := range allPerms {
		if strings.Contains(strings.ToLower(p.Name), qLower) || strings.Contains(strings.ToLower(p.Description), qLower) {
			perms = append(perms, SearchResult{Type: "permission", ID: p.Name, Name: p.Name, URL: "/admin/permissions?perm=" + p.Name})
		}
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string][]SearchResult{
		"users":       users,
		"groups":      groups,
		"clients":     clients,
		"permissions": perms,
	})
}
