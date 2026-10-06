package webserveur

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"vaultaire/core/action"
	"vaultaire/core/database"
	dbgroups "vaultaire/core/database/db_groups"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
)

// Arborescence de l'annuaire, côté web.
//
// # Ce qui a changé
//
// La page lisait la base directement et exigeait `write:eyes` — la clé
// qu'avait abandonnée la commande `eyes -g`. Deux conséquences :
//
//   - un délégué restreint à un domaine voyait l'arbre ENTIER, groupes et
//     comptes de toute l'organisation, alors que `eyes -g` le lui refusait ;
//   - il fallait une clé d'écriture pour une page qui ne fait que lire.
//
// L'arbre passe désormais par l'action `domain.list_tree` : même clé
// (`read:get:group`), même filtre, même résultat que la ligne de commande. Les
// COMPTES affichés sous chaque groupe exigent en plus `read:get:user` sur le
// domaine du groupe — voir un groupe n'autorise pas à lire ses membres, pas plus
// que `get -g` ne le fait.

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
	Name       string           `json:"name"`
	FullDomain string           `json:"full_domain,omitempty"`
	Children   []TreeDomainNode `json:"children,omitempty"`
	Groups     []TreeGroup      `json:"groups,omitempty"`
}

// buildTreeFromNode convertit un nœud en JSON.
//
// usersVisibles dit si les comptes d'un groupe du domaine donné peuvent être
// montrés. Un membre d'un groupe appartient au domaine de ce groupe : il suffit
// donc de tester le domaine du GROUPE, sans résoudre ceux de chaque compte.
func buildTreeFromNode(node *storage.DomainNode, db *sql.DB, usersVisibles func(domaine string) bool) TreeDomainNode {
	out := TreeDomainNode{
		Name:       node.Name,
		FullDomain: node.FullDomain,
		Groups:     make([]TreeGroup, 0, len(node.Groups)),
		Children:   nil,
	}
	montrerComptes := usersVisibles(node.FullDomain)
	for _, groupName := range node.Groups {
		tu := []TreeUser{}
		if montrerComptes {
			users, err := dbgroups.Command_GET_UsersByGroup(db, groupName)
			if err != nil {
				users = []storage.DisplayUsersByGroup{}
			}
			for _, u := range users {
				tu = append(tu, TreeUser{Username: u.Username, Connected: u.Connected})
			}
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
		out.Children = append(out.Children, buildTreeFromNode(child, db, usersVisibles))
	}
	return out
}

// AdminLDAPTreeAPIHandler serves the LDAP tree as JSON (domain → groups → users).
// Access: web_admin + read:get:group, filtered to the caller's scope — exactly
// like `eyes -g`, through the same action.
func AdminLDAPTreeAPIHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username, groupIDs, ok := requireWebAdminWithGroupIDs(w, r)
	if !ok {
		return
	}
	db := database.GetDatabase()
	res, err := action.Executer("domain.list_tree",
		action.Appelant{Username: username, GroupIDs: groupIDs}, action.Params{})
	if err != nil {
		var refus *action.ErrRefusee
		if errors.As(err, &refus) {
			http.Error(w, "Permission refusée : "+refus.Motif, http.StatusForbidden)
			return
		}
		logs.Write_LogCode("ERROR", logs.CodeWebAdmin, "webadmin ldap tree: load failed: "+err.Error())
		http.Error(w, "Erreur chargement groupes", http.StatusInternalServerError)
		return
	}
	groups, _ := res.Donnees.([]storage.GroupDomain)
	scopeUsers := newDomainScope(groupIDs, "read:get:user")
	usersVisibles := func(domaine string) bool { return scopeUsers.allowsAny([]string{domaine}) }
	root := action.ArbreDepuis(groups)
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
		payload.Tree = append(payload.Tree, buildTreeFromNode(root.Children[k], db, usersVisibles))
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeWebAdmin, "webadmin ldap tree: encode failed: "+err.Error())
		http.Error(w, "Erreur encodage", http.StatusInternalServerError)
	}
}

// GroupInfoAPI is the JSON response for GET /admin/api/group-info?group=...
type GroupInfoAPI struct {
	Name        string   `json:"name"`
	DomainName  string   `json:"domain_name"`
	Users       []string `json:"users"`
	Permissions []string `json:"permissions"`
	Clients     []string `json:"clients"`
	ClientPerms []string `json:"client_permissions"`
	GPOs        []string `json:"gpos"`
}

// AdminGroupInfoAPIHandler serves GET /admin/api/group-info?group=xxx (JSON group details).
// Access: web_admin + read:get:group (same as command get -g).
func AdminGroupInfoAPIHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_, groupIDs, ok := requireWebAdminWithGroupIDs(w, r)
	if !ok {
		return
	}
	if !checkWebAdminRBAC(w, r, groupIDs, "read:get:group") {
		return
	}
	groupName := r.URL.Query().Get("group")
	if groupName == "" {
		http.Error(w, "group required", http.StatusBadRequest)
		return
	}
	db := database.GetDatabase()
	info, err := dbgroups.Command_GET_GroupInfo(db, groupName)
	if err != nil || info == nil {
		http.Error(w, "group not found", http.StatusNotFound)
		return
	}
	// Un groupe hors du périmètre répond comme un groupe inexistant : dire
	// « refusé » confirmerait qu'il existe.
	domaines := []string{info.DomainName}
	if !newDomainScope(groupIDs, "read:get:group").allowsAny(domaines) {
		http.Error(w, "group not found", http.StatusNotFound)
		return
	}
	// Chaque rubrique suit la clé de ce qu'elle montre, sur le domaine du
	// groupe : voir un groupe n'autorise pas à lire ses membres, ses machines,
	// ses permissions ou ses GPO — pas plus que `get -g` ne le fait.
	voit := func(cle string) bool { return newDomainScope(groupIDs, cle).allowsAny(domaines) }
	out := GroupInfoAPI{Name: info.Name, DomainName: info.DomainName,
		Users: []string{}, Permissions: []string{}, Clients: []string{}, ClientPerms: []string{}, GPOs: []string{}}
	if voit("read:get:user") {
		out.Users = info.Users
	}
	if voit("read:get:permission") {
		out.Permissions = info.Permissions
		out.ClientPerms = info.ClientPerms
	}
	if voit("read:get:client") {
		out.Clients = info.Clients
	}
	if voit("read:get:gpo") {
		out.GPOs = info.GPOs
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(out)
}

// AdminTreePageHandler serves the LDAP tree page (HTML with dynamic tree).
// Access: web_admin + read:get:group (same key as command eyes -g).
func AdminTreePageHandler(w http.ResponseWriter, r *http.Request) {
	username, groupIDs, ok := requireWebAdminWithGroupIDs(w, r)
	if !ok {
		return
	}
	if !checkWebAdminRBAC(w, r, groupIDs, "read:get:group") {
		return
	}
	data := struct {
		Username  string
		DnsEnable bool
		Section   string
	}{Username: username, DnsEnable: storage.Dns_Enable, Section: "tree"}
	if err := executeAdminPage(w, "admin_tree.html", data); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeWebTemplate, "webadmin tree: template failed: "+err.Error())
		http.Error(w, "Template manquant", http.StatusInternalServerError)
	}
}
