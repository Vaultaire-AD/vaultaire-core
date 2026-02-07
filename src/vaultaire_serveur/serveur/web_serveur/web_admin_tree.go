package webserveur

import (
	"vaultaire/serveur/database"
	"vaultaire/serveur/domain"
	"vaultaire/serveur/logs"
	"vaultaire/serveur/storage"
	"database/sql"
	"encoding/json"
	"html/template"
	"net/http"
	"sort"
)

// TreeUser is a user in the LDAP tree API response.
type TreeUser struct {
	Username  string `json:"username"`
	Connected bool   `json:"connected"`
}

// TreeGroup is a group with its users in the API response.
type TreeGroup struct {
	Name  string     `json:"name"`
	Users []TreeUser `json:"users"`
}

// TreeDomainNode is a domain node with ordered children and groups for JSON.
type TreeDomainNode struct {
	Name     string            `json:"name"`
	FullDomain string          `json:"full_domain,omitempty"`
	Children []TreeDomainNode  `json:"children,omitempty"`
	Groups   []TreeGroup       `json:"groups,omitempty"`
}

func buildTreeFromNode(node *storage.DomainNode, db *sql.DB) TreeDomainNode {
	out := TreeDomainNode{
		Name:       node.Name,
		FullDomain: node.FullDomain,
		Groups:     make([]TreeGroup, 0, len(node.Groups)),
		Children:   nil,
	}
	for _, groupName := range node.Groups {
		users, err := database.Command_GET_UsersByGroup(db, groupName)
		if err != nil {
			users = []storage.DisplayUsersByGroup{}
		}
		tu := make([]TreeUser, 0, len(users))
		for _, u := range users {
			tu = append(tu, TreeUser{Username: u.Username, Connected: u.Connected})
		}
		out.Groups = append(out.Groups, TreeGroup{Name: groupName, Users: tu})
	}
	childKeys := make([]string, 0, len(node.Children))
	for k := range node.Children {
		childKeys = append(childKeys, k)
	}
	sort.Strings(childKeys)
	for _, k := range childKeys {
		child := node.Children[k]
		out.Children = append(out.Children, buildTreeFromNode(child, db))
	}
	return out
}

// AdminLDAPTreeAPIHandler serves the LDAP tree as JSON (domain → groups → users).
func AdminLDAPTreeAPIHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_, ok := requireWebAdmin(w, r)
	if !ok {
		return
	}
	db := database.GetDatabase()
	groups, err := database.GetAllGroupsWithDomains(db)
	if err != nil {
		logs.Write_Log("ERROR", "admin ldap tree: "+err.Error())
		http.Error(w, "Erreur chargement groupes", http.StatusInternalServerError)
		return
	}
	root := domain.BuildDomainTree(groups)
	// Root has children only (no groups at root); we expose its children as top-level
	var payload struct {
		Tree []TreeDomainNode `json:"tree"`
	}
	childKeys := make([]string, 0, len(root.Children))
	for k := range root.Children {
		childKeys = append(childKeys, k)
	}
	sort.Strings(childKeys)
	for _, k := range childKeys {
		payload.Tree = append(payload.Tree, buildTreeFromNode(root.Children[k], db))
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		logs.Write_Log("ERROR", "admin ldap tree encode: "+err.Error())
		http.Error(w, "Erreur encodage", http.StatusInternalServerError)
	}
}

// GroupInfoAPI is the JSON response for GET /admin/api/group-info?group=...
type GroupInfoAPI struct {
	Name         string   `json:"name"`
	DomainName   string   `json:"domain_name"`
	Users        []string `json:"users"`
	Permissions  []string `json:"permissions"`
	Clients      []string `json:"clients"`
	ClientPerms  []string `json:"client_permissions"`
	GPOs         []string `json:"gpos"`
}

// AdminGroupInfoAPIHandler serves GET /admin/api/group-info?group=xxx (JSON group details).
func AdminGroupInfoAPIHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_, ok := requireWebAdmin(w, r)
	if !ok {
		return
	}
	groupName := r.URL.Query().Get("group")
	if groupName == "" {
		http.Error(w, "group required", http.StatusBadRequest)
		return
	}
	db := database.GetDatabase()
	info, err := database.Command_GET_GroupInfo(db, groupName)
	if err != nil {
		http.Error(w, "group not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(GroupInfoAPI{
		Name:        info.Name,
		DomainName:  info.DomainName,
		Users:       info.Users,
		Permissions: info.Permissions,
		Clients:     info.Clients,
		ClientPerms: info.ClientPerms,
		GPOs:        info.GPOs,
	})
}

// AdminTreePageHandler serves the LDAP tree page (HTML with dynamic tree).
func AdminTreePageHandler(w http.ResponseWriter, r *http.Request) {
	username, ok := requireWebAdmin(w, r)
	if !ok {
		return
	}
	data := struct {
		Username  string
		DnsEnable bool
		Section   string
	}{Username: username, DnsEnable: storage.Dns_Enable, Section: "tree"}
	tmpl, err := template.ParseFiles("web_packet/sso_WEB_page/templates/admin_tree.html")
	if err != nil {
		logs.Write_Log("ERROR", "admin tree template: "+err.Error())
		http.Error(w, "Template manquant", http.StatusInternalServerError)
		return
	}
	if err := tmpl.Execute(w, data); err != nil {
		logs.Write_Log("ERROR", "admin tree execute: "+err.Error())
		http.Error(w, "Erreur serveur", http.StatusInternalServerError)
	}
}
