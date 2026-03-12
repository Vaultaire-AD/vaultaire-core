package webserveur

import (
	"vaultaire/serveur/database"
	dbcert "vaultaire/serveur/database/db-certificates"
	dbperm "vaultaire/serveur/database/db_permission"
	"vaultaire/serveur/ducky-network/new_client"
	"vaultaire/serveur/logs"
	"vaultaire/serveur/permission"
	"vaultaire/serveur/storage"
	"vaultaire/serveur/tools"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"database/sql"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func generateSalt(length int) ([]byte, error) {
	salt := make([]byte, length)
	_, err := rand.Read(salt)
	return salt, err
}

func getUniqueDomains(db *sql.DB) []string {
	groups, err := database.GetAllGroupsWithDomains(db)
	if err != nil {
		return nil
	}
	seen := make(map[string]struct{})
	var out []string
	for _, g := range groups {
		dname := strings.TrimSpace(g.DomainName)
		if dname == "" {
			continue
		}
		if _, ok := seen[dname]; !ok {
			seen[dname] = struct{}{}
			out = append(out, dname)
		}
	}
	return out
}

// AdminUsersHandler lists users or shows user detail when ?user= is set.
// Access: web_admin + read:get:user to view; write:create|update|delete|add:user for POST actions (same as command package).
func AdminUsersHandler(w http.ResponseWriter, r *http.Request) {
	username, groupIDs, ok := requireWebAdminWithGroupIDs(w, r)
	if !ok {
		return
	}
	if !checkWebAdminRBAC(w, r, groupIDs, "read:get:user") {
		return
	}
	db := database.GetDatabase()
	detailUser := r.URL.Query().Get("user")

	if detailUser != "" {
		// --- Detail view: one user ---
		detailData := struct {
			User      *storage.GetUserInfoSingle
			AllGroups []string
			UserPerms []string
			Message   string
			Username  string
			DnsEnable bool
			Section   string
		}{Username: username, DnsEnable: storage.Dns_Enable, Section: "users"}
		userInfo, err := database.Command_GET_UserInfo(db, detailUser)
		if err != nil {
			http.Error(w, "Utilisateur introuvable", http.StatusNotFound)
			return
		}
		detailData.User = userInfo
		userPerms, _ := dbperm.Command_GET_UserPermissionNamesByUsername(db, detailUser)
		detailData.UserPerms = userPerms
		allDetails, _ := database.Command_GET_GroupDetails(db)
		for _, g := range allDetails {
			detailData.AllGroups = append(detailData.AllGroups, g.GroupName)
		}

		if r.Method == http.MethodPost {
			action := r.FormValue("action")
			target := r.FormValue("target_user")
			if target == "" {
				target = detailUser
			}
			actionKey := ""
			switch action {
			case "update_user", "change_password":
				actionKey = "write:update:user"
			case "add_group":
				actionKey = "write:add:user"
			case "remove_group":
				actionKey = "write:delete:user"
			case "delete_user":
				actionKey = "write:delete:user"
			}
			if actionKey != "" && !checkWebAdminRBAC(w, r, groupIDs, actionKey) {
				return
			}
			switch action {
			case "update_user":
				uid, _ := database.Get_User_ID_By_Username(db, target)
				newUsername := r.FormValue("username")
				firstname := r.FormValue("firstname")
				lastname := r.FormValue("lastname")
				if err := database.Update_User_Info(db, uid, newUsername, firstname, lastname, "", ""); err != nil {
					detailData.Message = "Erreur : " + err.Error()
				} else {
					detailData.Message = "Profil mis à jour."
					if newUsername != detailUser {
						detailUser = newUsername
						userInfo, _ = database.Command_GET_UserInfo(db, newUsername)
						detailData.User = userInfo
					}
				}
			case "change_password":
				uid, _ := database.Get_User_ID_By_Username(db, target)
				password := r.FormValue("password")
				if password == "" {
					detailData.Message = "Mot de passe requis."
				} else {
					cur, _ := database.Command_GET_UserInfo(db, target)
					if cur == nil {
						detailData.Message = "Utilisateur introuvable."
					} else if err := database.Update_User_Info(db, uid, cur.Username, cur.Firstname, cur.Lastname, password, ""); err != nil {
						detailData.Message = "Erreur : " + err.Error()
					} else {
						detailData.Message = "Mot de passe changé."
					}
				}
			case "add_group":
				groupName := r.FormValue("group")
				if groupName != "" {
					if err := database.Command_ADD_UserToGroup(db, target, groupName); err != nil {
						detailData.Message = err.Error()
					} else {
						detailData.Message = "Ajouté au groupe."
						userInfo, _ = database.Command_GET_UserInfo(db, target)
						detailData.User = userInfo
					}
				}
			case "remove_group":
				groupName := r.FormValue("group")
				if groupName != "" {
					if err := database.Command_Remove_UserFromGroup(db, target, groupName); err != nil {
						detailData.Message = err.Error()
					} else {
						detailData.Message = "Retiré du groupe."
						userInfo, _ = database.Command_GET_UserInfo(db, target)
						detailData.User = userInfo
					}
				}
			case "delete_user":
				if err := database.Command_DELETE_UserWithUsername(db, target); err != nil {
					detailData.Message = err.Error()
				} else {
					http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
					return
				}
			}
			userPerms, _ = dbperm.Command_GET_UserPermissionNamesByUsername(db, detailUser)
			detailData.UserPerms = userPerms
		}

		if err := executeAdminPage(w, "admin_user_detail.html", detailData); err != nil {
			http.Error(w, "Template manquant", http.StatusInternalServerError)
			return
		}
		return
	}

	// --- List view ---
	data := struct {
		Username  string
		Users     []storage.GetUsers
		Message   string
		DnsEnable bool
		Section   string
	}{Username: username, DnsEnable: storage.Dns_Enable, Section: "users"}
	if r.Method == http.MethodPost {
		action := r.FormValue("action")
		if action == "create_user" && !checkWebAdminRBAC(w, r, groupIDs, "write:create:user") {
			return
		}
		if action == "delete_user" && !checkWebAdminRBAC(w, r, groupIDs, "write:delete:user") {
			return
		}
		switch action {
		case "create_user":
			u := r.FormValue("username")
			domain := r.FormValue("domain")
			password := r.FormValue("password")
			birthdate := r.FormValue("birthdate")
			firstname := r.FormValue("firstname")
			lastname := r.FormValue("lastname")
			if u == "" || domain == "" || password == "" {
				data.Message = "Username, domain et mot de passe requis."
			} else if strings.ToLower(u) == "vaultaire" {
				data.Message = "Ce nom d'utilisateur est réservé."
			} else {
				if _, err := tools.StringToDate(birthdate); err != nil {
					data.Message = "Date de naissance invalide (format DD/MM/YYYY)."
				} else {
					salt, err := generateSalt(16)
					if err != nil {
						data.Message = "Erreur génération salt."
					} else {
						saltHex := hex.EncodeToString(salt)
						salted := append(salt, []byte(password)...)
						hash := sha256.Sum256(salted)
						hashHex := hex.EncodeToString(hash[:])
						email := u + "@" + domain
						if firstname == "" {
							firstname = u
						}
						if lastname == "" {
							lastname = u
						}
						err = database.Create_New_User(db, u, firstname, lastname, email, hashHex, saltHex, birthdate, time.Now().Format("2006-01-02 15:04:05"))
						if err != nil {
							data.Message = "Erreur création : " + err.Error()
							logs.Write_LogCode("ERROR", logs.CodeWebAdmin, "webadmin: create user failed: "+err.Error())
						} else {
							data.Message = "Utilisateur créé."
						}
					}
				}
			}
		case "delete_user":
			u := r.FormValue("username")
			if u != "" {
				if err := database.Command_DELETE_UserWithUsername(db, u); err != nil {
					data.Message = "Erreur suppression : " + err.Error()
				} else {
					data.Message = "Utilisateur supprimé."
				}
			}
		}
	}
	users, err := database.Command_GET_AllUsers(db)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeWebAdmin, "webadmin: list users failed: "+err.Error())
		http.Error(w, "Erreur liste utilisateurs", http.StatusInternalServerError)
		return
	}
	data.Users = users
	if err := executeAdminPage(w, "admin_users.html", data); err != nil {
		http.Error(w, "Template manquant", http.StatusInternalServerError)
		return
	}
}

// AdminGroupsHandler lists groups or shows group detail when ?group= is set.
// Access: web_admin + read:get:group to view; write:create|delete|add:group|user|client|permission for POST (same as command package).
func AdminGroupsHandler(w http.ResponseWriter, r *http.Request) {
	username, groupIDs, ok := requireWebAdminWithGroupIDs(w, r)
	if !ok {
		return
	}
	if !checkWebAdminRBAC(w, r, groupIDs, "read:get:group") {
		return
	}
	db := database.GetDatabase()
	detailGroup := r.URL.Query().Get("group")

	if detailGroup != "" {
		info, err := database.Command_GET_GroupInfo(db, detailGroup)
		if err != nil {
			http.Error(w, "Groupe introuvable", http.StatusNotFound)
			return
		}
		detailData := struct {
			Group      string
			Users      []string
			Clients    []string
			Perms      []string
			AllUsers   []storage.GetUsers
			AllClients []storage.GetClientsByPermission
			AllPerms   []storage.UserPermission
			Message    string
			Username   string
			DnsEnable  bool
			Section    string
		}{Group: info.Name, Users: info.Users, Clients: info.Clients, Perms: info.Permissions, Username: username, DnsEnable: storage.Dns_Enable, Section: "groups"}

		if r.Method == http.MethodPost {
			action := r.FormValue("action")
			targetGroup := r.FormValue("target_group")
			if targetGroup == "" {
				targetGroup = detailGroup
			}
			actionKey := ""
			switch action {
			case "add_user":
				actionKey = "write:add:user"
			case "remove_user":
				actionKey = "write:delete:user"
			case "add_client":
				actionKey = "write:add:client"
			case "remove_client":
				actionKey = "write:delete:client"
			case "add_permission":
				actionKey = "write:add:permission"
			case "remove_permission":
				actionKey = "write:delete:group"
			case "delete_group":
				actionKey = "write:delete:group"
			}
			if actionKey != "" && !checkWebAdminRBAC(w, r, groupIDs, actionKey) {
				return
			}
			switch action {
			case "add_user":
				u := r.FormValue("username")
				if u != "" && database.Command_ADD_UserToGroup(db, u, targetGroup) == nil {
					detailData.Message = "Utilisateur ajouté."
					info, _ = database.Command_GET_GroupInfo(db, targetGroup)
					detailData.Users, detailData.Clients, detailData.Perms = info.Users, info.Clients, info.Permissions
				} else if u != "" {
					detailData.Message = "Erreur ajout (déjà membre ?)."
				}
			case "remove_user":
				u := r.FormValue("username")
				if u != "" && database.Command_Remove_UserFromGroup(db, u, targetGroup) == nil {
					detailData.Message = "Utilisateur retiré."
					info, _ = database.Command_GET_GroupInfo(db, targetGroup)
					detailData.Users, detailData.Clients, detailData.Perms = info.Users, info.Clients, info.Permissions
				}
			case "add_client":
				cid := r.FormValue("computeur_id")
				if cid != "" && database.Command_ADD_SoftwareToGroup(db, cid, targetGroup) == nil {
					detailData.Message = "Client ajouté."
					info, _ = database.Command_GET_GroupInfo(db, targetGroup)
					detailData.Users, detailData.Clients, detailData.Perms = info.Users, info.Clients, info.Permissions
				}
			case "remove_client":
				cid := r.FormValue("computeur_id")
				if cid != "" && database.Command_Remove_SoftwareFromGroup(db, cid, targetGroup) == nil {
					detailData.Message = "Client retiré."
					info, _ = database.Command_GET_GroupInfo(db, targetGroup)
					detailData.Users, detailData.Clients, detailData.Perms = info.Users, info.Clients, info.Permissions
				}
			case "add_permission":
				p := r.FormValue("permission")
				if p != "" && dbperm.Command_ADD_UserPermissionToGroup(db, p, targetGroup) == nil {
					detailData.Message = "Permission ajoutée."
					info, _ = database.Command_GET_GroupInfo(db, targetGroup)
					detailData.Perms = info.Permissions
				} else if p != "" {
					detailData.Message = "Erreur (déjà attribuée ?)."
				}
			case "remove_permission":
				p := r.FormValue("permission")
				if p != "" && database.Command_Remove_UserPermissionFromGroup(db, targetGroup, p) == nil {
					detailData.Message = "Permission retirée."
					info, _ = database.Command_GET_GroupInfo(db, targetGroup)
					detailData.Perms = info.Permissions
				}
			case "delete_group":
				if database.Command_DELETE_GroupWithGroupName(db, targetGroup) == nil {
					http.Redirect(w, r, "/admin/groups", http.StatusSeeOther)
					return
				}
				detailData.Message = "Erreur suppression."
			}
		}
		allUsers, _ := database.Command_GET_AllUsers(db)
		allClients, _ := database.Command_GET_AllClients(db)
		allPerms, _ := dbperm.Command_GET_AllUserPermissions(db)
		detailData.AllUsers, detailData.AllClients, detailData.AllPerms = allUsers, allClients, allPerms

		_ = executeAdminPage(w, "admin_group_detail.html", detailData)
		return
	}

	data := struct {
		Groups    []storage.GroupDetails
		Message   string
		Username  string
		DnsEnable bool
		Section   string
	}{Username: username, DnsEnable: storage.Dns_Enable, Section: "groups"}
	if r.Method == http.MethodPost {
		action := r.FormValue("action")
		if action == "create_group" && !checkWebAdminRBAC(w, r, groupIDs, "write:create:group") {
			return
		}
		if action == "delete_group" && !checkWebAdminRBAC(w, r, groupIDs, "write:delete:group") {
			return
		}
		switch action {
		case "create_group":
			groupName := r.FormValue("group_name")
			domain := r.FormValue("domain")
			if groupName == "" || domain == "" {
				data.Message = "Nom du groupe et domaine requis."
			} else {
				_, err := database.CreateGroup(db, groupName, domain)
				if err != nil {
					data.Message = "Erreur création : " + err.Error()
					logs.Write_LogCode("ERROR", logs.CodeWebAdmin, "webadmin: create group failed: "+err.Error())
				} else {
					data.Message = "Groupe créé."
				}
			}
		case "delete_group":
			groupName := r.FormValue("group_name")
			if groupName != "" {
				if err := database.Command_DELETE_GroupWithGroupName(db, groupName); err != nil {
					data.Message = "Erreur suppression : " + err.Error()
				} else {
					data.Message = "Groupe supprimé."
				}
			}
		}
	}
	groups, err := database.Command_GET_GroupDetails(db)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeWebAdmin, "webadmin: list groups failed: "+err.Error())
		http.Error(w, "Erreur liste groupes", http.StatusInternalServerError)
		return
	}
	data.Groups = groups
	if err := executeAdminPage(w, "admin_groups.html", data); err != nil {
		http.Error(w, "Template manquant", http.StatusInternalServerError)
	}
}

// AdminClientsHandler lists clients or shows client detail when ?client= is set.
// Access: web_admin + read:get:client to view; write:create|update|delete:client for POST (same as command package).
func AdminClientsHandler(w http.ResponseWriter, r *http.Request) {
	username, groupIDs, ok := requireWebAdminWithGroupIDs(w, r)
	if !ok {
		return
	}
	if !checkWebAdminRBAC(w, r, groupIDs, "read:get:client") {
		return
	}
	db := database.GetDatabase()
	detailClient := r.URL.Query().Get("client")

	if detailClient != "" {
		client, err := database.Command_GET_ClientByComputeurID(db, detailClient)
		if err != nil {
			http.Error(w, "Client introuvable", http.StatusNotFound)
			return
		}
		detailData := struct {
			Client    *storage.Software
			Message   string
			Username  string
			DnsEnable bool
			Section   string
		}{Client: client, Username: username, DnsEnable: storage.Dns_Enable, Section: "clients"}
		if r.Method == http.MethodPost {
			action := r.FormValue("action")
			targetClient := r.FormValue("target_client")
			if targetClient == "" {
				targetClient = detailClient
			}
			actionKey := ""
			switch action {
			case "update_client":
				actionKey = "write:update:client"
			case "delete_client":
				actionKey = "write:delete:client"
			}
			if actionKey != "" && !checkWebAdminRBAC(w, r, groupIDs, actionKey) {
				return
			}
			switch action {
			case "update_client":
				hostname := r.FormValue("hostname")
				osVal := r.FormValue("os")
				ram := r.FormValue("ram")
				proc := r.FormValue("proc")
				if err := database.UpdateHostname(db, targetClient, hostname, osVal, ram, proc); err != nil {
					detailData.Message = err.Error()
				} else {
					detailData.Message = "Client mis à jour."
					client, _ = database.Command_GET_ClientByComputeurID(db, targetClient)
					detailData.Client = client
				}
			case "delete_client":
				if database.Command_DELETE_ClientWithComputeurID(db, targetClient) == nil {
					http.Redirect(w, r, "/admin/clients", http.StatusSeeOther)
					return
				}
				detailData.Message = "Erreur suppression."
			}
		}
		_ = executeAdminPage(w, "admin_client_detail.html", detailData)
		return
	}

	data := struct {
		Clients   []storage.GetClientsByPermission
		Message   string
		Username  string
		DnsEnable bool
		Section   string
	}{Username: username, DnsEnable: storage.Dns_Enable, Section: "clients"}
	if r.Method == http.MethodPost {
		action := r.FormValue("action")
		if action == "create_client" && !checkWebAdminRBAC(w, r, groupIDs, "write:create:client") {
			return
		}
		if action == "delete_client" && !checkWebAdminRBAC(w, r, groupIDs, "write:delete:client") {
			return
		}
		switch action {
		case "create_client":
			logicielType := r.FormValue("logiciel_type")
			isServeurStr := r.FormValue("is_serveur")
			if logicielType == "" {
				data.Message = "Type du client requis."
			} else {
				isServeur := isServeurStr == "1"
				computeurID, err := newclient.GenerateClientSoftware(logicielType, isServeur)
				if err != nil {
					data.Message = "Erreur création : " + err.Error()
					logs.Write_LogCode("ERROR", logs.CodeWebAdmin, "webadmin: create client failed: "+err.Error())
				} else {
					data.Message = "Client créé avec ID : " + computeurID
				}
			}
		case "delete_client":
			computeurID := r.FormValue("computeur_id")
			if computeurID != "" {
				if err := database.Command_DELETE_ClientWithComputeurID(db, computeurID); err != nil {
					data.Message = "Erreur suppression : " + err.Error()
				} else {
					data.Message = "Client supprimé."
				}
			}
		}
	}
	clients, err := database.Command_GET_AllClients(db)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeWebAdmin, "webadmin: list clients failed: "+err.Error())
		http.Error(w, "Erreur liste clients", http.StatusInternalServerError)
		return
	}
	data.Clients = clients
	if err := executeAdminPage(w, "admin_clients.html", data); err != nil {
		http.Error(w, "Template manquant", http.StatusInternalServerError)
	}
}

// PermissionActionRow est une ligne d'action pour le détail permission (template).
type PermissionActionRow struct{ Field, Label, Value string }

// PermissionActionGroup est un groupe d'actions pour le détail permission (template).
type PermissionActionGroup struct {
	GroupName string
	Actions   []PermissionActionRow
}

// buildPermissionActionsGrouped construit les actions groupées par catégorie pour une lecture plus claire.
func buildPermissionActionsGrouped(db *sql.DB, perm *storage.UserPermission) []PermissionActionGroup {
	row := func(field, label, value string) PermissionActionRow { return PermissionActionRow{field, label, value} }
	legacy := []PermissionActionRow{
		row("auth", "Auth", perm.Auth),
		row("compare", "Compare", perm.Compare),
		row("search", "Search", perm.Search),
		row("web_admin", "Web admin", perm.Web_admin),
		row("none", "None", perm.None),
	}
	objectLabels := map[string]string{
		"user": "Utilisateurs (user)", "group": "Groupes (group)", "client": "Clients (client)",
		"permission": "Permissions (permission)", "gpo": "GPO",
	}
	groups := []PermissionActionGroup{{GroupName: "Legacy", Actions: legacy}}
	byObject := map[string][]PermissionActionRow{}
	for _, key := range permission.AllRBACActionKeys() {
		val, _ := dbperm.Command_GET_UserPermissionAction(db, int64(perm.ID), key)
		parts := strings.SplitN(key, ":", 3)
		obj := ""
		if len(parts) == 3 {
			obj = parts[2]
		}
		label := objectLabels[obj]
		if label == "" {
			label = obj
		}
		byObject[obj] = append(byObject[obj], PermissionActionRow{key, key, val})
	}
	for _, obj := range []string{"user", "group", "client", "permission", "gpo"} {
		if actions, ok := byObject[obj]; ok {
			name := objectLabels[obj]
			groups = append(groups, PermissionActionGroup{GroupName: name, Actions: actions})
		}
	}
	special := []PermissionActionRow{}
	for _, key := range []string{"write:dns", "write:eyes"} {
		val, _ := dbperm.Command_GET_UserPermissionAction(db, int64(perm.ID), key)
		special = append(special, PermissionActionRow{key, key, val})
	}
	groups = append(groups, PermissionActionGroup{GroupName: "Spécial (DNS, Eyes)", Actions: special})
	return groups
}

// AdminPermissionsHandler lists permissions or shows permission detail when ?perm= is set.
// Access: web_admin + read:get:permission to view; write:create|update|delete:permission for POST (same as command package).
func AdminPermissionsHandler(w http.ResponseWriter, r *http.Request) {
	username, groupIDs, ok := requireWebAdminWithGroupIDs(w, r)
	if !ok {
		return
	}
	if !checkWebAdminRBAC(w, r, groupIDs, "read:get:permission") {
		return
	}
	db := database.GetDatabase()
	detailPerm := r.URL.Query().Get("perm")

	if detailPerm != "" {
		perm, err := dbperm.Command_GET_UserPermissionByName(db, detailPerm)
		if err != nil || perm == nil {
			http.Error(w, "Permission introuvable", http.StatusNotFound)
			return
		}
		groups, _ := dbperm.Command_GET_Groups_ByUserPermission(db, detailPerm)
		allDomains := getUniqueDomains(db)
		groupedActions := buildPermissionActionsGrouped(db, perm)
		detailData := struct {
				Perm           *storage.UserPermission
				Groups         []string
				AllDomains     []string
				GroupedActions []PermissionActionGroup
				Message        string
				Username       string
				DnsEnable      bool
				Section        string
			}{Perm: perm, Groups: groups, AllDomains: allDomains, GroupedActions: groupedActions, Username: username, DnsEnable: storage.Dns_Enable, Section: "permissions"}
		if r.Method == http.MethodPost {
			action := r.FormValue("action")
			if action == "delete_permission" && !checkWebAdminRBAC(w, r, groupIDs, "write:delete:permission") {
				return
			}
			if action == "update_permission_action" && !checkWebAdminRBAC(w, r, groupIDs, "write:update:permission") {
				return
			}
			switch action {
			case "delete_permission":
				if r.FormValue("target_perm") == detailPerm && dbperm.Command_DELETE_UserPermissionByName(db, detailPerm) == nil {
					http.Redirect(w, r, "/admin/permissions", http.StatusSeeOther)
					return
				}
				detailData.Message = "Erreur suppression."
			case "update_permission_action":
				field := r.FormValue("field")
				op := r.FormValue("op")
				domain := strings.TrimSpace(r.FormValue("domain"))
				if domain == "" {
					domain = strings.TrimSpace(r.FormValue("domain_remove"))
				}
				propagation := r.FormValue("propagation")
				if propagation == "" {
					propagation = "0"
				}
				permID, errID := dbperm.Command_GET_UserPermissionID(db, detailPerm)
				if errID != nil {
					detailData.Message = "Permission introuvable."
					break
				}
				current, errGet := dbperm.Command_GET_UserPermissionAction(db, permID, field)
				if errGet != nil {
					detailData.Message = "Erreur lecture action: " + errGet.Error()
					break
				}
				parsed := permission.ParsePermissionAction(current)
				switch op {
				case "nil":
					_ = dbperm.Command_SET_UserPermissionAction(db, permID, field, "nil")
					detailData.Message = "Action " + field + " mise à nil."
				case "all":
					_ = dbperm.Command_SET_UserPermissionAction(db, permID, field, "all")
					detailData.Message = "Action " + field + " mise à all."
				case "add":
					if domain != "" {
						permission.UpdatePermissionAction(&parsed, domain, propagation, true)
						newVal := permission.ConvertPermissionActionToString(parsed)
						if err := dbperm.Command_SET_UserPermissionAction(db, permID, field, newVal); err != nil {
							detailData.Message = "Erreur: " + err.Error()
						} else {
							detailData.Message = "Domaine " + domain + " ajouté."
						}
					} else {
						detailData.Message = "Domaine requis."
					}
				case "remove":
					if domain != "" {
						permission.UpdatePermissionAction(&parsed, domain, propagation, false)
						newVal := "nil"
						if len(parsed.WithPropagation) > 0 || len(parsed.WithoutPropagation) > 0 {
							newVal = permission.ConvertPermissionActionToString(parsed)
						}
						_ = dbperm.Command_SET_UserPermissionAction(db, permID, field, newVal)
						detailData.Message = "Domaine " + domain + " retiré."
					}
				default:
					detailData.Message = "Opération invalide."
				}
				perm, _ = dbperm.Command_GET_UserPermissionByName(db, detailPerm)
				detailData.Perm = perm
				detailData.GroupedActions = buildPermissionActionsGrouped(db, perm)
			}
		}
		_ = executeAdminPage(w, "admin_permission_detail.html", detailData)
		return
	}

	data := struct {
		Perms     []storage.UserPermission
		Message   string
		Username  string
		DnsEnable bool
		Section   string
	}{Username: username, DnsEnable: storage.Dns_Enable, Section: "permissions"}
	if r.Method == http.MethodPost {
		action := r.FormValue("action")
		if action == "create_permission" && !checkWebAdminRBAC(w, r, groupIDs, "write:create:permission") {
			return
		}
		if action == "delete_permission" && !checkWebAdminRBAC(w, r, groupIDs, "write:delete:permission") {
			return
		}
		switch action {
		case "create_permission":
			name := r.FormValue("name")
			description := r.FormValue("description")
			if name == "" {
				data.Message = "Nom de la permission requis."
			} else {
				_, err := dbperm.CreateUserPermissionDefault(db, name, description)
				if err != nil {
					data.Message = "Erreur création : " + err.Error()
					logs.Write_LogCode("ERROR", logs.CodeWebAdmin, "webadmin: create permission failed: "+err.Error())
				} else {
					data.Message = "Permission créée."
				}
			}
		case "delete_permission":
			permName := r.FormValue("permission_name")
			if permName != "" {
				if err := dbperm.Command_DELETE_UserPermissionByName(db, permName); err != nil {
					data.Message = "Erreur suppression : " + err.Error()
				} else {
					data.Message = "Permission supprimée."
				}
			}
		}
	}
	perms, err := dbperm.Command_GET_AllUserPermissions(db)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeWebAdmin, "webadmin: list permissions failed: "+err.Error())
		http.Error(w, "Erreur liste permissions", http.StatusInternalServerError)
		return
	}
	data.Perms = perms
	if err := executeAdminPage(w, "admin_permissions.html", data); err != nil {
		http.Error(w, "Template manquant", http.StatusInternalServerError)
	}
}

// AdminCertificatesHandler lists certificates or shows certificate detail when ?cert= is set.
// Access: web_admin only (no specific RBAC key for certificates; same as before).
func AdminCertificatesHandler(w http.ResponseWriter, r *http.Request) {
	username, ok := requireWebAdmin(w, r)
	if !ok {
		return
	}

	detailCertID := r.URL.Query().Get("cert")
	if detailCertID != "" {
		certID, err := strconv.Atoi(detailCertID)
		if err != nil {
			http.Error(w, "ID certificat invalide", http.StatusBadRequest)
			return
		}
		cert, err := dbcert.GetCertificateByID(certID)
		if err != nil {
			http.Error(w, "Certificat introuvable", http.StatusNotFound)
			return
		}
		// Ne jamais exposer la clé privée dans l'interface web
		cert.PrivateKeyData = nil
		detailData := struct {
			Certificate *storage.Certificate
			Message     string
			Username    string
			DnsEnable   bool
			Section     string
		}{Certificate: cert, Username: username, DnsEnable: storage.Dns_Enable, Section: "certificates"}
		if r.Method == http.MethodPost {
			action := r.FormValue("action")
			switch action {
			case "delete_certificate":
				if err := dbcert.DeleteCertificate(certID); err != nil {
					detailData.Message = "Erreur suppression : " + err.Error()
				} else {
					http.Redirect(w, r, "/admin/certificates", http.StatusSeeOther)
					return
				}
			}
		}
		_ = executeAdminPage(w, "admin_certificate_detail.html", detailData)
		return
	}

	data := struct {
		Certificates []storage.Certificate
		Message      string
		Username     string
		DnsEnable    bool
		Section      string
	}{Username: username, DnsEnable: storage.Dns_Enable, Section: "certificates"}

	if r.Method == http.MethodPost {
		action := r.FormValue("action")
		switch action {
		case "delete_certificate":
			certIDStr := r.FormValue("certificate_id")
			if certIDStr != "" {
				certID, err := strconv.Atoi(certIDStr)
				if err != nil {
					data.Message = "ID certificat invalide"
				} else {
					if err := dbcert.DeleteCertificate(certID); err != nil {
						data.Message = "Erreur suppression : " + err.Error()
					} else {
						data.Message = "Certificat supprimé."
					}
				}
			}
		}
	}

	certificates, err := dbcert.GetAllCertificates()
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeWebAdmin, "webadmin: list certificates failed: "+err.Error())
		http.Error(w, "Erreur liste certificats", http.StatusInternalServerError)
		return
	}
	data.Certificates = certificates

	if err := executeAdminPage(w, "admin_certificates.html", data); err != nil {
		http.Error(w, "Template manquant", http.StatusInternalServerError)
	}
}

// AdminLogsHandler affiche la page des logs avec filtres.
// Access: web_admin + read:get:user (same as command get -u for viewing data).
func AdminLogsHandler(w http.ResponseWriter, r *http.Request) {
	username, groupIDs, ok := requireWebAdminWithGroupIDs(w, r)
	if !ok {
		return
	}
	if !checkWebAdminRBAC(w, r, groupIDs, "read:get:user") {
		return
	}

	data := struct {
		Username  string
		DnsEnable bool
		Section   string
		Stats     map[string]interface{}
	}{
		Username:  username,
		DnsEnable: storage.Dns_Enable,
		Section:   "logs",
		Stats:     logs.GetLogsStats(),
	}

	if err := executeAdminPage(w, "admin_logs.html", data); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeWebTemplate, "webadmin: template admin_logs.html missing: "+err.Error())
		http.Error(w, "Template manquant", http.StatusInternalServerError)
	}
}

// AdminLogsAPIHandler retourne les logs filtrés en JSON.
// Access: web_admin + read:get:user.
func AdminLogsAPIHandler(w http.ResponseWriter, r *http.Request) {
	_, groupIDs, ok := requireWebAdminWithGroupIDs(w, r)
	if !ok {
		http.Error(w, "Non autorisé", http.StatusUnauthorized)
		return
	}
	allowed, _ := permission.CheckPermissionsMultipleDomains(groupIDs, "read:get:user", []string{"*"})
	if !allowed {
		http.Error(w, "Permission refusée", http.StatusForbidden)
		return
	}

	levelFilter := r.URL.Query().Get("level")
	codeFilter := r.URL.Query().Get("code")
	limitStr := r.URL.Query().Get("limit")

	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 1000 {
			limit = l
		}
	}

	entries, err := logs.GetLogsForWebUI(levelFilter, codeFilter, limit)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeWebAdmin, "webadmin: logs retrieval failed: "+err.Error())
		http.Error(w, "Erreur récupération logs", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"logs":  entries,
		"count": len(entries),
		"stats": logs.GetLogsStats(),
	})
}
