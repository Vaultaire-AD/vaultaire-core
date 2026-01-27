package webserveur

import (
	"DUCKY/serveur/database"
	dbperm "DUCKY/serveur/database/db_permission"
	"DUCKY/serveur/logs"
	"DUCKY/serveur/permission"
	"DUCKY/serveur/web_serveur/session"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"html/template"
	"net/http"
	"strings"
	"time"
)

// helper: vérifie session et permission web_admin
func requireWebAdmin(w http.ResponseWriter, r *http.Request) (string, bool) {
	tokenCookie, err := r.Cookie("session_token")
	if err != nil || tokenCookie.Value == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return "", false
	}
	username, valid := session.ValidateToken(tokenCookie.Value)
	if !valid {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return "", false
	}

	groupsID, action, err := permission.PrePermissionCheck(username, "web_admin")
	if err != nil {
		logs.Write_Log("WARNING", "PrePermissionCheck échoué pour user "+username+": "+err.Error())
		http.Error(w, "Permission refusée", http.StatusForbidden)
		return "", false
	}
	ok, reason := permission.CheckPermissionsMultipleDomains(groupsID, action, []string{"*"})
	if !ok {
		logs.Write_Log("WARNING", "Accès admin refusé pour "+username+" : "+reason)
		http.Error(w, "Accès admin refusé : "+reason, http.StatusForbidden)
		return "", false
	}

	// prolonger la session
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    tokenCookie.Value,
		HttpOnly: true,
		Secure:   true,
		Path:     "/",
		Expires:  time.Now().Add(30 * time.Minute),
	})

	return username, true
}

// Dashboard admin — redirige vers la liste utilisateurs
func AdminIndexHandler(w http.ResponseWriter, r *http.Request) {
	_, ok := requireWebAdmin(w, r)
	if !ok {
		return
	}
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

// Liste tous les utilisateurs
func AdminUsersHandler(w http.ResponseWriter, r *http.Request) {
	username, ok := requireWebAdmin(w, r)
	if !ok {
		return
	}
	// Si un utilisateur spécifique est demandé => page détail / édition
	targetUser := r.URL.Query().Get("user")
	message := ""
	// If POST from a detail form, the browser may omit the query string — accept hidden field fallback
	if r.Method == "POST" {
		_ = r.ParseForm()
		if t := r.FormValue("target_user"); t != "" {
			targetUser = t
		}
	}
	if targetUser != "" {
		// Detail view
		if r.Method == "POST" {
			if err := r.ParseForm(); err == nil {
				action := r.FormValue("action")
				switch action {
				case "update_user":
					newUsername := r.FormValue("username")
					firstname := r.FormValue("firstname")
					lastname := r.FormValue("lastname")
					password := r.FormValue("password")
					// Récupérer id
					userID, err := database.Get_User_ID_By_Username(database.GetDatabase(), targetUser)
					if err == nil {
						if err := database.Update_User_Info(database.GetDatabase(), userID, newUsername, firstname, lastname, password, ""); err != nil {
							message = "Erreur update user: " + err.Error()
						} else {
							message = "Utilisateur mis à jour"
							// update targetUser for reload
							targetUser = newUsername
						}
					} else {
						message = "Utilisateur introuvable"
					}
				case "change_password":
					pass := r.FormValue("password")
					if pass != "" {
						userID, err := database.Get_User_ID_By_Username(database.GetDatabase(), targetUser)
						if err == nil {
							if err := database.Update_User_Info(database.GetDatabase(), userID, targetUser, "", "", pass, ""); err != nil {
								message = "Erreur changement mot de passe: " + err.Error()
							} else {
								message = "Mot de passe mis à jour"
							}
						}
					}
				case "add_group":
					group := r.FormValue("group")
					if group != "" {
						if err := database.Command_ADD_UserToGroup(database.GetDatabase(), targetUser, group); err != nil {
							message = "Erreur ajout au groupe: " + err.Error()
						} else {
							message = "Ajouté au groupe " + group
						}
					}
				case "remove_group":
					group := r.FormValue("group")
					if group != "" {
						if err := database.Command_Remove_UserFromGroup(database.GetDatabase(), targetUser, group); err != nil {
							message = "Erreur retrait du groupe: " + err.Error()
						} else {
							message = "Retiré du groupe " + group
						}
					}
				case "delete_user":
					if err := database.Command_DELETE_UserWithUsername(database.GetDatabase(), targetUser); err != nil {
						message = "Erreur suppression utilisateur: " + err.Error()
					} else {
						http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
						return
					}
				}
			}
		}

		// Render detail
		userInfo, err := database.Command_GET_UserInfo(database.GetDatabase(), targetUser)
		if err != nil {
			http.Error(w, "Utilisateur introuvable", http.StatusNotFound)
			return
		}

		groups, _ := database.Command_GET_GroupDetails(database.GetDatabase())
		// build list of group names
		var allGroups []string
		for _, g := range groups {
			allGroups = append(allGroups, g.GroupName)
		}

		// Aggregate permissions from user's groups (unique)
		permSet := make(map[string]bool)
		for _, gname := range userInfo.Groups {
			grpInfo, err := database.Command_GET_GroupInfo(database.GetDatabase(), gname)
			if err == nil {
				for _, p := range grpInfo.Permissions {
					if p != "" {
						permSet[p] = true
					}
				}
			}
		}
		var userPerms []string
		for p := range permSet {
			userPerms = append(userPerms, p)
		}

		tmpl, err := template.ParseFiles("web_packet/sso_WEB_page/templates/admin_user_detail.html")
		if err != nil {
			logs.Write_Log("ERROR", "Template admin_user_detail manquant: "+err.Error())
			http.Error(w, "Template manquant", http.StatusInternalServerError)
			return
		}

		data := struct {
			Username  string
			User      interface{}
			AllGroups []string
			UserPerms []string
			Message   string
		}{Username: username, User: userInfo, AllGroups: allGroups, Message: message}
		data.UserPerms = userPerms
		_ = tmpl.Execute(w, data)
		return
	}

	// actions POST (list view)
	if r.Method == "POST" {
		if err := r.ParseForm(); err == nil {
			action := r.FormValue("action")
			switch action {
			case "delete_user":
				target := r.FormValue("username")
				if target != "" {
					if err := database.Command_DELETE_UserWithUsername(database.GetDatabase(), target); err != nil {
						message = "Erreur suppression utilisateur: " + err.Error()
					} else {
						message = "Utilisateur supprimé: " + target
					}
				}
			case "create_user":
				// expected fields: username, domain, password, birthdate, firstname, lastname
				uname := strings.TrimSpace(r.FormValue("username"))
				domain := strings.TrimSpace(r.FormValue("domain"))
				password := r.FormValue("password")
				birthdate := r.FormValue("birthdate")
				firstname := r.FormValue("firstname")
				lastname := r.FormValue("lastname")
				if uname != "" && domain != "" && password != "" {
					// generate salt+hash
					salt := make([]byte, 16)
					_, _ = rand.Read(salt)
					saltHex := hex.EncodeToString(salt)
					salted := append(salt, []byte(password)...)
					hash := sha256.Sum256(salted)
					hashHex := hex.EncodeToString(hash[:])
					email := uname + "@" + domain
					if err := database.Create_New_User(database.GetDatabase(), uname, firstname, lastname, email, hashHex, saltHex, birthdate, time.Now().Format("2006-01-02 15:04:05")); err != nil {
						message = "Erreur création utilisateur: " + err.Error()
					} else {
						message = "Utilisateur créé: " + uname
					}
				} else {
					message = "Champs manquants pour création"
				}
			}
		}
	}

	users, err := database.Command_GET_AllUsers(database.GetDatabase())
	if err != nil {
		logs.Write_Log("ERROR", "Erreur récupération utilisateurs: "+err.Error())
		http.Error(w, "Erreur interne", http.StatusInternalServerError)
		return
	}

	tmpl, err := template.ParseFiles("web_packet/sso_WEB_page/templates/admin_users.html")
	if err != nil {
		logs.Write_Log("ERROR", "Template admin_users manquant: "+err.Error())
		http.Error(w, "Template manquant", http.StatusInternalServerError)
		return
	}

	data := struct {
		Username string
		Users    interface{}
		Message  string
	}{Username: username, Users: users, Message: message}

	if err := tmpl.Execute(w, data); err != nil {
		logs.Write_Log("ERROR", "Erreur execution template admin_users: "+err.Error())
	}
}

// Liste des groupes
func AdminGroupsHandler(w http.ResponseWriter, r *http.Request) {
	username, ok := requireWebAdmin(w, r)
	if !ok {
		return
	}
	targetGroup := r.URL.Query().Get("group")
	message := ""
	if r.Method == "POST" {
		_ = r.ParseForm()
		if t := r.FormValue("target_group"); t != "" {
			targetGroup = t
		}
	}

	if targetGroup != "" {
		// Group detail view
		if r.Method == "POST" {
			if err := r.ParseForm(); err == nil {
				action := r.FormValue("action")
				switch action {
				case "add_user":
					user := r.FormValue("username")
					if user != "" {
						if err := database.Command_ADD_UserToGroup(database.GetDatabase(), user, targetGroup); err != nil {
							message = "Erreur ajout user: " + err.Error()
						} else {
							message = "Utilisateur ajouté au groupe"
						}
					}
				case "remove_user":
					user := r.FormValue("username")
					if user != "" {
						if err := database.Command_Remove_UserFromGroup(database.GetDatabase(), user, targetGroup); err != nil {
							message = "Erreur retrait user: " + err.Error()
						} else {
							message = "Utilisateur retiré"
						}
					}
				case "add_client":
					client := r.FormValue("computeur_id")
					if client != "" {
						if err := database.Command_ADD_SoftwareToGroup(database.GetDatabase(), client, targetGroup); err != nil {
							message = "Erreur ajout client: " + err.Error()
						} else {
							message = "Client ajouté"
						}
					}
				case "remove_client":
					client := r.FormValue("computeur_id")
					if client != "" {
						if err := database.Command_Remove_SoftwareFromGroup(database.GetDatabase(), client, targetGroup); err != nil {
							message = "Erreur retrait client: " + err.Error()
						} else {
							message = "Client retiré"
						}
					}
				case "add_permission":
					perm := r.FormValue("permission")
					if perm != "" {
						if err := dbperm.Command_ADD_UserPermissionToGroup(database.GetDatabase(), perm, targetGroup); err != nil {
							message = "Erreur ajout permission: " + err.Error()
						} else {
							message = "Permission ajoutée"
						}
					}
				case "remove_permission":
					perm := r.FormValue("permission")
					if perm != "" {
						if err := database.Command_Remove_UserPermissionFromGroup(database.GetDatabase(), targetGroup, perm); err != nil {
							message = "Erreur retrait permission: " + err.Error()
						} else {
							message = "Permission retirée"
						}
					}
				case "delete_group":
					if err := database.Command_DELETE_GroupWithGroupName(database.GetDatabase(), targetGroup); err != nil {
						message = "Erreur suppression groupe: " + err.Error()
					} else {
						http.Redirect(w, r, "/admin/groups", http.StatusSeeOther)
						return
					}
				}
			}
		}

		// render detail
		// use consolidated group info
		groupInfo, _ := database.Command_GET_GroupInfo(database.GetDatabase(), targetGroup)

		// all users/clients/permissions for selection
		allUsers, _ := database.Command_GET_AllUsers(database.GetDatabase())
		allClients, _ := database.Command_GET_AllClients(database.GetDatabase())
		allPerms, _ := dbperm.Command_GET_AllUserPermissions(database.GetDatabase())

		tmpl, err := template.ParseFiles("web_packet/sso_WEB_page/templates/admin_group_detail.html")
		if err != nil {
			logs.Write_Log("ERROR", "Template admin_group_detail manquant: "+err.Error())
			http.Error(w, "Template manquant", http.StatusInternalServerError)
			return
		}

		data := struct {
			Username   string
			Group      string
			Users      interface{}
			Clients    interface{}
			Perms      interface{}
			AllUsers   interface{}
			AllClients interface{}
			AllPerms   interface{}
			Message    string
		}{Username: username, Group: targetGroup, Users: groupInfo.Users, Clients: groupInfo.Clients, Perms: groupInfo.Permissions, AllUsers: allUsers, AllClients: allClients, AllPerms: allPerms, Message: message}
		_ = tmpl.Execute(w, data)
		return
	}

	// list view: create/delete groups
	if r.Method == "POST" {
		if err := r.ParseForm(); err == nil {
			action := r.FormValue("action")
			switch action {
			case "delete_group":
				target := r.FormValue("group_name")
				if target != "" {
					if err := database.Command_DELETE_GroupWithGroupName(database.GetDatabase(), target); err != nil {
						message = "Erreur suppression groupe: " + err.Error()
					} else {
						message = "Groupe supprimé: " + target
					}
				}
			case "create_group":
				grp := r.FormValue("group_name")
				domain := r.FormValue("domain")
				if grp != "" && domain != "" {
					if _, err := database.CreateGroup(database.GetDatabase(), grp, domain); err != nil {
						message = "Erreur création groupe: " + err.Error()
					} else {
						message = "Groupe créé: " + grp
					}
				} else {
					message = "Champs manquants"
				}
			}
		}
	}

	groups, err := database.Command_GET_GroupDetails(database.GetDatabase())
	if err != nil {
		logs.Write_Log("ERROR", "Erreur récupération groups: "+err.Error())
		http.Error(w, "Erreur interne", http.StatusInternalServerError)
		return
	}

	tmpl, err := template.ParseFiles("web_packet/sso_WEB_page/templates/admin_groups.html")
	if err != nil {
		logs.Write_Log("ERROR", "Template admin_groups manquant: "+err.Error())
		http.Error(w, "Template manquant", http.StatusInternalServerError)
		return
	}

	data := struct {
		Username string
		Groups   interface{}
		Message  string
	}{Username: username, Groups: groups, Message: message}
	_ = tmpl.Execute(w, data)
}

// Liste des clients
func AdminClientsHandler(w http.ResponseWriter, r *http.Request) {
	username, ok := requireWebAdmin(w, r)
	if !ok {
		return
	}

	message := ""
	targetClient := r.URL.Query().Get("client")
	if r.Method == "POST" {
		_ = r.ParseForm()
		if t := r.FormValue("target_client"); t != "" {
			targetClient = t
		}
		// also accept computeur_id as fallback for older templates
		if targetClient == "" && r.FormValue("computeur_id") != "" {
			targetClient = r.FormValue("computeur_id")
		}
	}
	if targetClient != "" {
		// detail view
		if r.Method == "POST" {
			if err := r.ParseForm(); err == nil {
				action := r.FormValue("action")
				switch action {
				case "update_client":
					hostname := r.FormValue("hostname")
					os := r.FormValue("os")
					ram := r.FormValue("ram")
					proc := r.FormValue("proc")
					if err := database.UpdateHostname(database.GetDatabase(), targetClient, hostname, os, ram, proc); err != nil {
						message = "Erreur mise à jour client: " + err.Error()
					} else {
						message = "Client mis à jour"
					}
				case "delete_client":
					if err := database.Command_DELETE_ClientWithComputeurID(database.GetDatabase(), targetClient); err != nil {
						message = "Erreur suppression client: " + err.Error()
					} else {
						http.Redirect(w, r, "/admin/clients", http.StatusSeeOther)
						return
					}
				}
			}
		}

		clientInfo, err := database.Command_GET_ClientByComputeurID(database.GetDatabase(), targetClient)
		if err != nil {
			http.Error(w, "Client introuvable", http.StatusNotFound)
			return
		}

		tmpl, err := template.ParseFiles("web_packet/sso_WEB_page/templates/admin_client_detail.html")
		if err != nil {
			logs.Write_Log("ERROR", "Template admin_client_detail manquant: "+err.Error())
			http.Error(w, "Template manquant", http.StatusInternalServerError)
			return
		}

		data := struct {
			Username string
			Client   interface{}
			Message  string
		}{Username: username, Client: clientInfo, Message: message}
		_ = tmpl.Execute(w, data)
		return
	}

	// list view with create/delete
	if r.Method == "POST" {
		if err := r.ParseForm(); err == nil {
			action := r.FormValue("action")
			switch action {
			case "delete_client":
				target := r.FormValue("computeur_id")
				if target != "" {
					if err := database.Command_DELETE_ClientWithComputeurID(database.GetDatabase(), target); err != nil {
						message = "Erreur suppression client: " + err.Error()
					} else {
						message = "Client supprimé: " + target
					}
				}
			case "create_client":
				computeur := r.FormValue("computeur_id")
				ltype := r.FormValue("logiciel_type")
				pubkey := r.FormValue("public_key")
				isServeur := r.FormValue("is_serveur") == "1"
				if computeur != "" && ltype != "" {
					if err := database.Create_ClientSoftware(database.GetDatabase(), computeur, ltype, pubkey, isServeur); err != nil {
						message = "Erreur création client: " + err.Error()
					} else {
						message = "Client créé: " + computeur
					}
				} else {
					message = "Champs manquants pour création client"
				}
			}
		}
	}

	clients, err := database.Command_GET_AllClients(database.GetDatabase())
	if err != nil {
		logs.Write_Log("ERROR", "Erreur récupération clients: "+err.Error())
		http.Error(w, "Erreur interne", http.StatusInternalServerError)
		return
	}

	tmpl, err := template.ParseFiles("web_packet/sso_WEB_page/templates/admin_clients.html")
	if err != nil {
		logs.Write_Log("ERROR", "Template admin_clients manquant: "+err.Error())
		http.Error(w, "Template manquant", http.StatusInternalServerError)
		return
	}

	data := struct {
		Username string
		Clients  interface{}
		Message  string
	}{Username: username, Clients: clients, Message: message}
	_ = tmpl.Execute(w, data)
}

// Liste des permissions utilisateurs
func AdminPermissionsHandler(w http.ResponseWriter, r *http.Request) {
	username, ok := requireWebAdmin(w, r)
	if !ok {
		return
	}

	message := ""
	targetPerm := r.URL.Query().Get("perm")
	if r.Method == "POST" {
		_ = r.ParseForm()
		if t := r.FormValue("target_perm"); t != "" {
			targetPerm = t
		}
		if targetPerm == "" && r.FormValue("permission_name") != "" {
			targetPerm = r.FormValue("permission_name")
		}
	}

	if targetPerm != "" {
		// detail / edit permission (for now allow delete)
		if r.Method == "POST" {
			if err := r.ParseForm(); err == nil {
				action := r.FormValue("action")
				switch action {
				case "delete_permission":
					if err := dbperm.Command_DELETE_UserPermissionByName(database.GetDatabase(), targetPerm); err != nil {
						message = "Erreur suppression permission: " + err.Error()
					} else {
						http.Redirect(w, r, "/admin/permissions", http.StatusSeeOther)
						return
					}
				}
			}
		}

		permInfo, err := dbperm.Command_GET_UserPermissionByName(database.GetDatabase(), targetPerm)
		if err != nil {
			http.Error(w, "Permission introuvable", http.StatusNotFound)
			return
		}
		// groups providing this permission
		groupsWithPerm, _ := dbperm.Command_GET_Groups_ByUserPermission(database.GetDatabase(), targetPerm)
		tmpl, err := template.ParseFiles("web_packet/sso_WEB_page/templates/admin_permission_detail.html")
		if err != nil {
			logs.Write_Log("ERROR", "Template admin_permission_detail manquant: "+err.Error())
			http.Error(w, "Template manquant", http.StatusInternalServerError)
			return
		}
		data := struct {
			Username string
			Perm     interface{}
			Groups   interface{}
			Message  string
		}{Username: username, Perm: permInfo, Groups: groupsWithPerm, Message: message}
		_ = tmpl.Execute(w, data)
		return
	}

	if r.Method == "POST" {
		if err := r.ParseForm(); err == nil {
			action := r.FormValue("action")
			switch action {
			case "delete_permission":
				target := r.FormValue("permission_name")
				if target != "" {
					if err := dbperm.Command_DELETE_UserPermissionByName(database.GetDatabase(), target); err != nil {
						message = "Erreur suppression permission: " + err.Error()
					} else {
						message = "Permission supprimée: " + target
					}
				}
			case "create_permission":
				name := r.FormValue("name")
				desc := r.FormValue("description")
				if name != "" {
					if _, err := dbperm.CreateUserPermissionDefault(database.GetDatabase(), name, desc); err != nil {
						message = "Erreur création permission: " + err.Error()
					} else {
						message = "Permission créée: " + name
					}
				}
			}
		}
	}

	perms, err := dbperm.Command_GET_AllUserPermissions(database.GetDatabase())
	if err != nil {
		logs.Write_Log("ERROR", "Erreur récupération permissions: "+err.Error())
		http.Error(w, "Erreur interne", http.StatusInternalServerError)
		return
	}

	tmpl, err := template.ParseFiles("web_packet/sso_WEB_page/templates/admin_permissions.html")
	if err != nil {
		logs.Write_Log("ERROR", "Template admin_permissions manquant: "+err.Error())
		http.Error(w, "Template manquant", http.StatusInternalServerError)
		return
	}

	data := struct {
		Username string
		Perms    interface{}
		Message  string
	}{Username: username, Perms: perms, Message: message}
	_ = tmpl.Execute(w, data)
}
