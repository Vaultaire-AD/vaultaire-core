package webserveur

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	clusterdatabase "vaultaire/cluster/cluster_database"
	"vaultaire/core/database"
	dbcert "vaultaire/core/database/db-certificates"
	dbgpo "vaultaire/core/database/db_gpo"
	dbperm "vaultaire/core/database/db_permission"
	dbrevocation "vaultaire/core/database/db_revocation"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
	"vaultaire/core/revocation"
	"vaultaire/core/storage"
	"vaultaire/core/tools"
	newclient "vaultaire/ducky-network/new_client"
	revocationmanager "vaultaire/ducky-network/revocation_manager"
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
			Error     string
			Username  string
			DnsEnable bool
			Section   string
			// Kill switch : état de révocation du compte affiché, et historique
			// des ordres. L'historique survit à une suppression hard, c'est même
			// sa raison d'être — mais la page n'est alors plus atteignable, donc
			// il ne sert ici qu'aux verrouillages soft et à leurs levées.
			IsRevoked   bool
			Revocations []dbrevocation.Record
			KillReasons []revocation.Reason
			CanKill     bool
		}{Username: username, DnsEnable: storage.Dns_Enable, Section: "users",
			KillReasons: revocation.AllReasons()}
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
			// Kill switch : les contrôles RBAC sont faits par Trigger, qui
			// exige write:killswitch sur tous les domaines de la cible (et
			// write:delete:user en plus pour le mode hard). On ne les redouble
			// pas ici — un contrôle dupliqué finit toujours par diverger de
			// celui qui compte.
			if action == "kill_user" {
				mode := revocation.Mode(r.FormValue("kill_mode"))
				reason := revocation.Reason(r.FormValue("kill_reason"))

				// Le mode destructeur exige de retaper le nom du compte. Ce
				// n'est pas une confirmation de confort : hard supprime le
				// compte et son répertoire personnel sur tout le parc, sans
				// retour possible. Le mode soft, réversible, n'en demande pas.
				if mode == revocation.ModeHard && r.FormValue("confirm_username") != target {
					detailData.Error = "Suppression définitive : saisissez exactement le nom du compte pour confirmer."
					action = ""
				} else if out, err := revocationmanager.Trigger(username, groupIDs, target, mode, reason); err != nil {
					detailData.Error = err.Error()
					action = ""
				} else {
					if mode == revocation.ModeHard {
						// Le compte n'existe plus : rester sur sa page
						// afficherait une fiche vide.
						http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
						return
					}
					detailData.Message = fmt.Sprintf(
						"Ordre %d — %s. %d machine(s) visée(s), %d jointe(s) immédiatement, %d session(s) fermée(s).",
						out.OrderID, out.Mode.Label(), out.TargetCount, out.PushedNow, out.SessionsKilled)
					action = ""
				}
			}

			// Le droit est exigé sur les domaines de l'utilisateur visé, et sur
			// tous. Un utilisateur membre de groupes dans plusieurs domaines
			// n'est administrable que par quelqu'un qui les couvre tous : sinon
			// un délégué d'un seul domaine pourrait changer le mot de passe
			// d'un compte qui détient des droits ailleurs.
			if actionKey != "" {
				domains := entityDomainsOrGlobal(permission.GetDomainListFromUsername(target))
				if allowed, reason := checkWebAdminRBACOnDomains(groupIDs, actionKey, domains); !allowed {
					logs.Write_Log("SECURITY", fmt.Sprintf(
						"webadmin: %s tente %s sur l'utilisateur %s — %s", username, action, target, reason))
					detailData.Message = "Permission refusée : " + reason
					action = ""
				}
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

		// État de révocation relu APRÈS les actions : un verrouillage qui vient
		// d'être posé ou levé doit se voir immédiatement sur la page.
		detailData.IsRevoked = dbrevocation.IsRevoked(db, detailUser)
		detailData.Revocations, _ = dbrevocation.HistoryFor(db, detailUser)
		detailData.CanKill = permission.HasActionAnywhere(groupIDs, permission.ActionKillSwitch)

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
		// Les permissions client et les GPO étaient déjà lues par
		// Command_GET_GroupInfo mais n'étaient exposées nulle part dans
		// l'interface : elles n'étaient gérables qu'en ligne de commande.
		detailData := struct {
			Group          string
			Users          []string
			Clients        []string
			Perms          []string
			ClientPerms    []string
			GPOs           []string
			AllUsers       []storage.GetUsers
			AllClients     []storage.GetClientsByPermission
			AllPerms       []storage.UserPermission
			AllClientPerms []storage.ClientPermission
			AllGPOs        []string
			Message        string
			Error          string
			Username       string
			DnsEnable      bool
			Section        string
		}{
			Group: info.Name, Users: info.Users, Clients: info.Clients,
			Perms: info.Permissions, ClientPerms: info.ClientPerms, GPOs: info.GPOs,
			Username: username, DnsEnable: storage.Dns_Enable, Section: "groups",
		}

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
			case "add_client_permission":
				actionKey = "write:add:permission"
			case "remove_client_permission":
				actionKey = "write:delete:permission"
			case "add_gpo":
				actionKey = "write:add:gpo"
			case "remove_gpo":
				actionKey = "write:delete:gpo"
			case "delete_group":
				actionKey = "write:delete:group"
			}
			// Le droit est exigé sur les domaines du groupe visé. Un groupe
			// porte les permissions et les GPO de ses membres : y ajouter un
			// utilisateur, une machine ou une permission revient à distribuer
			// des droits dans ce ou ces domaines.
			if actionKey != "" {
				domains := entityDomainsOrGlobal(permission.GetDomainsFromGroupName(targetGroup))
				if allowed, reason := checkWebAdminRBACOnDomains(groupIDs, actionKey, domains); !allowed {
					logs.Write_Log("SECURITY", fmt.Sprintf(
						"webadmin: %s tente %s sur le groupe %s — %s", username, action, targetGroup, reason))
					detailData.Message = "Permission refusée : " + reason
					action = ""
				}
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

			case "add_client_permission":
				p := r.FormValue("client_permission")
				if p != "" {
					if err := database.Command_ADD_PermissionToSoftwareGroup(db, p, targetGroup); err != nil {
						detailData.Error = "Permission client : " + err.Error()
					} else {
						detailData.Message = "Permission client ajoutée."
					}
				}
			case "remove_client_permission":
				p := r.FormValue("client_permission")
				if p != "" {
					if err := database.Command_Remove_ClientPermissionFromGroup(db, targetGroup, p); err != nil {
						detailData.Error = "Permission client : " + err.Error()
					} else {
						detailData.Message = "Permission client retirée."
					}
				}

			case "add_gpo":
				g := r.FormValue("gpo")
				if g != "" {
					if err := dbgpo.LinkPolicyToGroup(db, g, targetGroup); err != nil {
						detailData.Error = "GPO : " + err.Error()
					} else {
						detailData.Message = "GPO liée au groupe."
					}
				}
			case "remove_gpo":
				g := r.FormValue("gpo")
				if g != "" {
					if err := dbgpo.UnlinkPolicyFromGroup(db, g, targetGroup); err != nil {
						detailData.Error = "GPO : " + err.Error()
					} else {
						detailData.Message = "GPO retirée du groupe."
					}
				}

			case "delete_group":
				if database.Command_DELETE_GroupWithGroupName(db, targetGroup) == nil {
					http.Redirect(w, r, "/admin/groups", http.StatusSeeOther)
					return
				}
				detailData.Message = "Erreur suppression."
			}

			// Relecture après toute action : plusieurs sections dépendent du même
			// enregistrement, et n'en rafraîchir qu'une afficherait un état
			// partiellement périmé juste après une modification.
			if refreshed, err := database.Command_GET_GroupInfo(db, targetGroup); err == nil {
				info = refreshed
				detailData.Users, detailData.Clients = info.Users, info.Clients
				detailData.Perms, detailData.ClientPerms = info.Permissions, info.ClientPerms
				detailData.GPOs = info.GPOs
			}
		}

		allUsers, _ := database.Command_GET_AllUsers(db)
		allClients, _ := database.Command_GET_AllClients(db)
		allPerms, _ := dbperm.Command_GET_AllUserPermissions(db)
		allClientPerms, _ := database.Command_GET_AllClientPermissions(db)
		detailData.AllUsers, detailData.AllClients = allUsers, allClients
		detailData.AllPerms, detailData.AllClientPerms = allPerms, allClientPerms

		// Seules les GPO non encore liées sont proposées à l'ajout : offrir une
		// GPO déjà présente ne produirait qu'une erreur « déjà liée ».
		if policies, err := dbgpo.GetAllPolicies(db); err == nil {
			linked := make(map[string]bool, len(detailData.GPOs))
			for _, name := range detailData.GPOs {
				linked[name] = true
			}
			for _, p := range policies {
				if !linked[p.Name] {
					detailData.AllGPOs = append(detailData.AllGPOs, p.Name)
				}
			}
		}

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
			// Le droit est exigé sur les domaines de la machine visée.
			if actionKey != "" {
				domains := entityDomainsOrGlobal(permission.GetDomainsFromClientByComputerID(targetClient))
				if allowed, reason := checkWebAdminRBACOnDomains(groupIDs, actionKey, domains); !allowed {
					logs.Write_Log("SECURITY", fmt.Sprintf(
						"webadmin: %s tente %s sur le client %s — %s", username, action, targetClient, reason))
					detailData.Message = "Permission refusée : " + reason
					action = ""
				}
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

// permissionTabs liste les onglets de la page de détail d'une permission.
var permissionTabs = []string{"matrix", "groups", "settings"}

// permissionListTabs liste les onglets de la page liste des permissions.
var permissionListTabs = []string{"users", "clients", "create"}

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
		detailData := struct {
			Perm       *storage.UserPermission
			Groups     []string
			AllDomains []string
			Matrix     permissionMatrixView
			// Editor est la case ouverte dans l'éditeur unique. Une seule action
			// est éditable à la fois : c'est ce qui rend la page insensible au
			// nombre d'objets RBAC déclarés.
			Editor     permissionCell
			HasEditor  bool
			GroupCount int
			Message    string
			Error      string
			Username   string
			DnsEnable  bool
			Section    string
			ActiveTab  string
		}{Perm: perm, Groups: groups, AllDomains: allDomains,
			Username: username, DnsEnable: storage.Dns_Enable, Section: "permissions"}
		if r.Method == http.MethodPost {
			action := r.FormValue("action")
			detailData.ActiveTab = sanitizeTabFrom(r.FormValue("active_tab"), permissionTabs)
			// Les domaines d'une permission sont ceux des groupes qui la
			// portent : la modifier change les droits dans tous ces domaines à
			// la fois, donc on les exige tous.
			permActionKey := ""
			switch action {
			case "delete_permission":
				permActionKey = "write:delete:permission"
			case "update_permission_action":
				permActionKey = "write:update:permission"
			}
			if permActionKey != "" {
				domains := entityDomainsOrGlobal(permission.GetDomainslistFromUserpermission(detailPerm))
				if allowed, reason := checkWebAdminRBACOnDomains(groupIDs, permActionKey, domains); !allowed {
					logs.Write_Log("SECURITY", fmt.Sprintf(
						"webadmin: %s tente %s sur la permission %s — %s", username, action, detailPerm, reason))
					detailData.Error = "Permission refusée : " + reason
					action = ""
				}
			}
			switch action {
			case "delete_permission":
				if r.FormValue("target_perm") == detailPerm && dbperm.Command_DELETE_UserPermissionByName(db, detailPerm) == nil {
					http.Redirect(w, r, "/admin/permissions", http.StatusSeeOther)
					return
				}
				detailData.Message = "Erreur suppression."
			case "update_permission_action":
				field := strings.TrimSpace(r.FormValue("field"))
				op := r.FormValue("op")
				domain := strings.TrimSpace(r.FormValue("domain"))
				if domain == "" {
					domain = strings.TrimSpace(r.FormValue("domain_remove"))
				}
				propagation := r.FormValue("propagation")
				if propagation == "" {
					propagation = "0"
				}

				// Le champ vient d'un formulaire : il est vérifié contre la
				// liste des actions réellement administrables. Sans ce contrôle,
				// une clé inventée s'insérerait dans user_permission_action et
				// y resterait — jamais évaluée par le moteur RBAC, donc sans
				// effet, mais indétectable dans l'interface.
				if !permissionFieldExists(field) {
					logs.Write_Log("SECURITY", "webadmin: "+username+" tente d'écrire l'action inconnue '"+field+"' sur la permission "+detailPerm)
					detailData.Error = "Action inconnue."
					break
				}

				// Une action évaluée uniquement sur « * » n'accepte que nil ou
				// all. Lui donner des domaines la refuse au lieu de la
				// restreindre — et pour web_admin, cela retire l'accès à
				// l'interface d'administration, y compris à l'auteur du
				// changement. Le refus est ici et pas seulement dans le
				// formulaire : l'interface ne doit jamais être la seule barrière.
				if permission.IsGlobalOnlyAction(field) && (op == "add" || op == "remove") {
					detailData.Error = "L'action " + field + " s'évalue sur tous les domaines : elle accepte seulement nil ou all."
					break
				}

				permID, errID := dbperm.Command_GET_UserPermissionID(db, detailPerm)
				if errID != nil {
					detailData.Error = "Permission introuvable."
					break
				}
				current, errGet := dbperm.Command_GET_UserPermissionAction(db, permID, field)
				if errGet != nil {
					detailData.Error = "Erreur lecture action: " + errGet.Error()
					break
				}
				parsed := permission.ParsePermissionAction(current)
				switch op {
				case "nil":
					if err := dbperm.Command_SET_UserPermissionAction(db, permID, field, "nil"); err != nil {
						detailData.Error = "Erreur: " + err.Error()
					} else {
						detailData.Message = "Action " + field + " mise à nil."
					}
				case "all":
					if err := dbperm.Command_SET_UserPermissionAction(db, permID, field, "all"); err != nil {
						detailData.Error = "Erreur: " + err.Error()
					} else {
						detailData.Message = "Action " + field + " mise à all."
					}
				case "add":
					if domain == "" {
						detailData.Error = "Domaine requis."
						break
					}
					permission.UpdatePermissionAction(&parsed, domain, propagation, true)
					newVal := permission.ConvertPermissionActionToString(parsed)
					if err := dbperm.Command_SET_UserPermissionAction(db, permID, field, newVal); err != nil {
						detailData.Error = "Erreur: " + err.Error()
					} else {
						detailData.Message = "Domaine " + domain + " ajouté à " + field + "."
					}
				case "remove":
					if domain == "" {
						detailData.Error = "Domaine requis."
						break
					}
					// Le retrait doit désigner un domaine réellement présent.
					// UpdatePermissionAction est silencieux sur un domaine
					// absent : sans ce contrôle, une faute de frappe affichait
					// « domaine retiré » sans que rien n'ait changé.
					if !domainGranted(parsed, domain, propagation) {
						detailData.Error = "Le domaine " + domain + " n'est pas accordé sur " + field + "."
						break
					}
					permission.UpdatePermissionAction(&parsed, domain, propagation, false)
					newVal := "nil"
					if len(parsed.WithPropagation) > 0 || len(parsed.WithoutPropagation) > 0 {
						newVal = permission.ConvertPermissionActionToString(parsed)
					}
					if err := dbperm.Command_SET_UserPermissionAction(db, permID, field, newVal); err != nil {
						detailData.Error = "Erreur: " + err.Error()
					} else {
						detailData.Message = "Domaine " + domain + " retiré de " + field + "."
					}
				default:
					detailData.Error = "Opération invalide."
				}

				// L'éditeur reste ouvert sur l'action qu'on vient de modifier :
				// on enchaîne souvent plusieurs domaines sur la même action.
				detailData.Editor.Field = field

				// Relecture après écriture. Un échec conserve l'objet précédent
				// plutôt que de le remplacer par nil : la page affichera des
				// valeurs d'avant l'écriture, ce qui est déroutant, mais une
				// déréférence de nil planterait la requête entière.
				if reloaded, reloadErr := dbperm.Command_GET_UserPermissionByName(db, detailPerm); reloadErr == nil && reloaded != nil {
					perm = reloaded
					detailData.Perm = perm
				} else {
					detailData.Error = appendError(detailData.Error, "Relecture de la permission impossible, l'affichage peut être en retard.")
				}
			}
		}

		// Construction de la vue après les écritures, pour refléter la base et
		// non l'état supposé.
		detailData.Matrix = buildPermissionMatrix(db, detailData.Perm)
		detailData.GroupCount = len(groups)
		if detailData.ActiveTab == "" {
			detailData.ActiveTab = "matrix"
		}
		// L'action à ouvrir dans l'éditeur peut venir d'un POST précédent ou du
		// lien ?field= — dans les deux cas elle est relue depuis la matrice, pas
		// reconstruite, pour que l'éditeur montre la valeur réellement en base.
		editorField := detailData.Editor.Field
		if editorField == "" {
			editorField = r.URL.Query().Get("field")
		}
		if cell, ok := detailData.Matrix.editorCell(editorField); ok {
			detailData.Editor = cell
			detailData.HasEditor = true
		} else {
			detailData.Editor = permissionCell{}
		}

		if err := executeAdminPage(w, "admin_permission_detail.html", detailData); err != nil {
			logs.Write_LogCode("ERROR", logs.CodeWebTemplate, "webadmin: template admin_permission_detail.html: "+err.Error())
			http.Error(w, "Template manquant", http.StatusInternalServerError)
		}
		return
	}

	// Deux familles de permissions cohabitent et sont souvent confondues :
	// celles des UTILISATEURS (RBAC, LDAP, interface) et celles des CLIENTS
	// (les logiciels installés sur les machines). Les secondes n'étaient
	// gérables qu'en ligne de commande ; elles ont maintenant leur section.
	data := struct {
		Perms       []storage.UserPermission
		ClientPerms []storage.ClientPermission
		Message     string
		Error       string
		Username    string
		DnsEnable   bool
		Section     string
		UserCount   int
		ClientCount int
		ActiveTab   string
	}{Username: username, DnsEnable: storage.Dns_Enable, Section: "permissions"}
	if r.Method == http.MethodPost {
		action := r.FormValue("action")
		data.ActiveTab = sanitizeTabFrom(r.FormValue("active_tab"), permissionListTabs)
		if action == "create_permission" && !checkWebAdminRBAC(w, r, groupIDs, "write:create:permission") {
			return
		}
		if action == "delete_permission" && !checkWebAdminRBAC(w, r, groupIDs, "write:delete:permission") {
			return
		}
		if action == "create_client_permission" && !checkWebAdminRBAC(w, r, groupIDs, "write:create:permission") {
			return
		}
		if action == "delete_client_permission" && !checkWebAdminRBAC(w, r, groupIDs, "write:delete:permission") {
			return
		}
		if action == "update_client_permission" && !checkWebAdminRBAC(w, r, groupIDs, "write:update:permission") {
			return
		}
		switch action {
		case "update_client_permission":
			name := r.FormValue("permission_name")
			isAdmin := r.FormValue("is_admin") == "on"
			if name == "" {
				break
			}
			if err := dbperm.Command_UPDATE_ClientPermission(db, name, isAdmin); err != nil {
				data.Error = err.Error()
				break
			}
			data.Message = "Permission client mise à jour."
			// Accorder ou retirer l'administration à des machines est un
			// changement de privilège : il est tracé au même titre que la
			// création d'une permission admin.
			logs.Write_Log("SECURITY", fmt.Sprintf(
				"webadmin: permission client %q passee a admin=%t par %s", name, isAdmin, username))

		case "create_client_permission":
			name := strings.TrimSpace(r.FormValue("name"))
			isAdmin := r.FormValue("is_admin") == "on"
			if name == "" {
				data.Error = "Nom de la permission client requis."
				break
			}
			if _, err := dbperm.CreateClientPermission(db, name, isAdmin); err != nil {
				data.Error = "Erreur création : " + err.Error()
				logs.Write_LogCode("ERROR", logs.CodeWebAdmin, "webadmin: create client permission failed: "+err.Error())
			} else {
				data.Message = "Permission client créée."
				if isAdmin {
					// Une permission client admin donne les droits d'administration
					// aux machines du groupe qui la porte : la création mérite une
					// trace au même titre qu'un changement de privilège.
					logs.Write_Log("SECURITY", fmt.Sprintf(
						"webadmin: permission client ADMIN %q creee par %s", name, username))
				}
			}

		case "delete_client_permission":
			name := r.FormValue("permission_name")
			if name == "" {
				break
			}
			if err := dbperm.Command_DELETE_ClientPermissionByName(db, name); err != nil {
				data.Error = "Erreur suppression : " + err.Error()
			} else {
				data.Message = "Permission client supprimée."
			}

		case "create_permission":
			name := r.FormValue("name")
			description := r.FormValue("description")
			webAdmin := r.FormValue("web_admin") == "on"
			if name == "" {
				data.Error = "Nom de la permission requis."
				break
			}

			// Une permission utilisateur naissait avec toutes ses actions à
			// « nil » : il fallait la créer, ouvrir son détail, puis régler
			// web_admin pour qu'elle serve à quelque chose. Le raccourci évite
			// cet aller-retour pour le cas le plus courant.
			var err error
			if webAdmin {
				_, err = dbperm.CreateUserPermission(db, name, description, "nil", "all", "nil", "nil", "nil")
			} else {
				_, err = dbperm.CreateUserPermissionDefault(db, name, description)
			}
			if err != nil {
				data.Error = "Erreur création : " + err.Error()
				logs.Write_LogCode("ERROR", logs.CodeWebAdmin, "webadmin: create permission failed: "+err.Error())
				break
			}

			data.Message = "Permission créée. Ouvrez son détail pour régler les actions RBAC."
			if webAdmin {
				logs.Write_Log("SECURITY", fmt.Sprintf(
					"webadmin: permission utilisateur %q creee avec web_admin par %s", name, username))
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

	// L'échec de lecture des permissions client n'empêche pas d'afficher les
	// permissions utilisateur : la page reste utile, et le bandeau d'erreur
	// signale ce qui manque plutôt que de renvoyer une page blanche.
	clientPerms, err := database.Command_GET_AllClientPermissions(db)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeWebAdmin, "webadmin: list client permissions failed: "+err.Error())
		data.Error = appendError(data.Error, "Permissions client illisibles : "+err.Error())
	} else {
		data.ClientPerms = clientPerms
	}

	data.UserCount = len(data.Perms)
	data.ClientCount = len(data.ClientPerms)
	if data.ActiveTab == "" {
		data.ActiveTab = "users"
	}

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
				if !canDeleteCertificate(username) {
					detailData.Message = "Réservé aux membres du groupe " + database.ProtectedGroupName + "."
					break
				}
				if err := dbcert.DeleteCertificate(certID); err != nil {
					detailData.Message = "Erreur suppression : " + err.Error()
				} else {
					logs.Write_Log("SECURITY", fmt.Sprintf(
						"webadmin: certificat %d supprimé par %s", certID, username))
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
			if !canDeleteCertificate(username) {
				data.Message = "Réservé aux membres du groupe " + database.ProtectedGroupName + "."
				break
			}
			certIDStr := r.FormValue("certificate_id")
			if certIDStr != "" {
				certID, err := strconv.Atoi(certIDStr)
				if err != nil {
					data.Message = "ID certificat invalide"
				} else {
					if err := dbcert.DeleteCertificate(certID); err != nil {
						data.Message = "Erreur suppression : " + err.Error()
					} else {
						logs.Write_Log("SECURITY", fmt.Sprintf(
							"webadmin: certificat %d supprimé par %s", certID, username))
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

// AdminClusterHandler affiche l'état des nœuds du cluster (lecture seule).
// Accès: web_admin + read:get:client (même clé que pour la visibilité des clients).
func AdminClusterHandler(w http.ResponseWriter, r *http.Request) {
	username, groupIDs, ok := requireWebAdminWithGroupIDs(w, r)
	if !ok {
		return
	}
	if !checkWebAdminRBAC(w, r, groupIDs, "read:get:client") {
		return
	}

	db := database.GetDatabase()
	nodes, err := clusterdatabase.GetAllNodes(db)
	message := ""
	if err != nil {
		message = "Erreur récupération nœuds: " + err.Error()
	}

	data := struct {
		Username  string
		Nodes     interface{}
		Message   string
		DnsEnable bool
		Section   string
	}{
		Username:  username,
		Nodes:     nodes,
		Message:   message,
		DnsEnable: storage.Dns_Enable,
		Section:   "cluster",
	}

	if err := executeAdminPage(w, "admin_cluster.html", data); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeWebAdmin, "webadmin: template admin_cluster.html missing: "+err.Error())
		http.Error(w, "Template manquant", http.StatusInternalServerError)
	}
}
