package webserveur

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	dbclients "vaultaire/core/database/db_clients"
	dbdomains "vaultaire/core/database/db_domains"
	dbgroups "vaultaire/core/database/db_groups"
	dbusers "vaultaire/core/database/db_users"

	clusterdatabase "vaultaire/cluster/cluster_database"
	act "vaultaire/core/action"
	"vaultaire/core/database"
	dbauthpolicy "vaultaire/core/database/db_authpolicy"
	dbcertificates "vaultaire/core/database/db_certificates"
	dbgpo "vaultaire/core/database/db_gpo"
	dbpermission "vaultaire/core/database/db_permission"
	dbrevocation "vaultaire/core/database/db_revocation"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
	"vaultaire/core/revocation"
	"vaultaire/core/storage"
	revocationmanager "vaultaire/ducky-network/revocation_manager"
)

// generateSalt a été retirée : le sel et le haché du mot de passe sont produits
// par l'action user.create, une seule fois pour les deux façades.

func getUniqueDomains(db *sql.DB) []string {
	groups, err := dbdomains.GetAllGroupsWithDomains(db)
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
			// Second facteur : état du compte affiché, et droit de le
			// réinitialiser. HasActionAnywhere et non un contrôle sur « * » — le
			// droit se délègue par domaine, comme le kill switch, et le contrôle
			// strict sur tous les domaines de la cible est fait à l'action.
			MFAEnabled  bool
			CanResetMFA bool
		}{Username: username, DnsEnable: storage.Dns_Enable, Section: "users",
			KillReasons: revocation.AllReasons()}
		userInfo, err := dbusers.Command_GET_UserInfo(db, detailUser)
		if err != nil {
			http.Error(w, "Utilisateur introuvable", http.StatusNotFound)
			return
		}
		detailData.User = userInfo
		userPerms, _ := dbpermission.Command_GET_UserPermissionNamesByUsername(db, detailUser)
		detailData.UserPerms = userPerms
		allDetails, _ := dbgroups.Command_GET_GroupDetails(db)
		for _, g := range allDetails {
			detailData.AllGroups = append(detailData.AllGroups, g.GroupName)
		}

		if r.Method == http.MethodPost {
			action := r.FormValue("action")
			target := r.FormValue("target_user")
			if target == "" {
				target = detailUser
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

			// Les six autres actions de cette page passent par le registre.
			//
			// La table « action → clé RBAC » et le `if actionKey != ""` qui la
			// suivait ont disparu : ce motif sautait la vérification pour toute
			// action absente de la table.
			//
			// Deux ajouts sont venus du portage : la suppression refuse
			// désormais de viser votre propre compte, et le mot de passe vide
			// est refusé plutôt qu'accepté silencieusement.
			//
			// La cible vient de l'URL quand le formulaire ne la répète pas.
			res, traite, errAction := ExecuterActionFormulaireAvec(r, username, groupIDs,
				act.Params{"username": detailUser})

			if traite {
				if errAction != nil {
					detailData.Message = MessageDActionPourAffichage(res, errAction)
				} else {
					detailData.Message = res.Message

					// La suppression renvoie vers la liste : la fiche d'un
					// compte supprimé serait vide.
					if action == "delete_user" {
						http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
						return
					}

					// Un renommage change l'adresse de la page. La relecture
					// se fait sur le nouveau nom, sans quoi la fiche
					// afficherait un compte introuvable juste après une
					// modification réussie.
					if nouveau := r.FormValue("new_username"); nouveau != "" && nouveau != detailUser {
						detailUser = nouveau
					}
					if maj, err := dbusers.Command_GET_UserInfo(db, detailUser); err == nil {
						detailData.User = maj
					}
				}
			}
		}

		// État de révocation relu APRÈS les actions : un verrouillage qui vient
		// d'être posé ou levé doit se voir immédiatement sur la page.
		detailData.IsRevoked = dbrevocation.IsRevoked(db, detailUser)
		detailData.Revocations, _ = dbrevocation.HistoryFor(db, detailUser)
		detailData.CanKill = permission.HasActionAnywhere(groupIDs, permission.ActionKillSwitch)

		// Second facteur, relu après les actions pour la même raison : une
		// réinitialisation qui vient d'avoir lieu doit se voir sans recharger.
		if st, err := dbauthpolicy.GetAuthState(db, detailUser); err == nil {
			detailData.MFAEnabled = st.MFAEnabled && st.MFASecret != ""
		}
		detailData.CanResetMFA = permission.HasActionAnywhere(groupIDs, permission.ActionManageMFA)

		if err := executeAdminPage(w, "admin_user_detail.html", detailData); err != nil {
			http.Error(w, "Template manquant", http.StatusInternalServerError)
			return
		}
		return
	}

	// --- Vue liste ---
	data := struct {
		Username  string
		Users     []storage.GetUsers
		Message   string
		DnsEnable bool
		Section   string
	}{Username: username, DnsEnable: storage.Dns_Enable, Section: "users"}

	if r.Method == http.MethodPost {
		// Les actions user.create et user.delete portent leur clé RBAC et leur
		// portée. user.delete passe par la révocation : le compte est retiré du
		// parc, pas seulement de l'annuaire.
		res, traite, err := ExecuterActionFormulaire(r, username, groupIDs)
		if traite {
			if err != nil {
				data.Message = MessageDActionPourAffichage(res, err)
			} else {
				data.Message = res.Message
			}
		}
	}

	users, err := dbusers.Command_GET_AllUsers(db)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeWebAdmin, "webadmin: list users failed: "+err.Error())
		http.Error(w, "Erreur liste utilisateurs", http.StatusInternalServerError)
		return
	}
	// La liste est réduite au périmètre de l'appelant : ouvrir la page ne donne
	// pas le droit de voir tout l'annuaire.
	scope := newDomainScope(groupIDs, "read:get:user")
	filtered := filterUsers(scope, users)
	logScopeFiltering(username, "utilisateurs", len(users), len(filtered))
	data.Users = filtered
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
		info, err := dbgroups.Command_GET_GroupInfo(db, detailGroup)
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
			// MFARequired : le groupe impose-t-il le second facteur à ses membres ?
			// Porté par le groupe et non par le compte, pour qu'un nouvel arrivant
			// y soit soumis du seul fait de son entrée, sans geste à ne pas
			// oublier.
			MFARequired bool
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
			// Les treize actions de cette page passent par le registre.
			//
			// La table « action → clé RBAC » qui vivait ici a disparu, et avec
			// elle le `if actionKey != ""` qui la suivait : ce motif sautait la
			// vérification des droits pour toute action absente de la table,
			// sans erreur ni journal.
			//
			// Deux corrections de droits sont venues du portage :
			//
			//   - « remove_permission » exigeait write:delete:group, ce qui
			//     paraît être une faute de recopie — retirer une permission
			//     n'est pas supprimer le groupe. C'est write:delete:permission ;
			//   - les rattachements exigent maintenant le droit sur les domaines
			//     du groupe ET de l'entité rattachée. La ligne de commande ne
			//     contrôlait que l'un des deux, et pas toujours le même.
			//
			// Le groupe vient de l'URL quand le formulaire ne le répète pas.
			res, traite, errAction := ExecuterActionFormulaireAvec(r, username, groupIDs,
				act.Params{"group": targetGroup})

			if traite {
				if errAction != nil {
					detailData.Message = MessageDActionPourAffichage(res, errAction)
				} else {
					detailData.Message = res.Message

					// La suppression renvoie vers la liste : la page de détail
					// afficherait un groupe qui n'existe plus.
					if action == "delete_group" {
						http.Redirect(w, r, "/admin/groups", http.StatusSeeOther)
						return
					}
				}
			}

			// Relecture après toute action : plusieurs sections dépendent du même
			// enregistrement, et n'en rafraîchir qu'une afficherait un état
			// partiellement périmé juste après une modification.
			if refreshed, err := dbgroups.Command_GET_GroupInfo(db, targetGroup); err == nil {
				info = refreshed
				detailData.Users, detailData.Clients = info.Users, info.Clients
				detailData.Perms, detailData.ClientPerms = info.Permissions, info.ClientPerms
				detailData.GPOs = info.GPOs
			}
		}

		allUsers, _ := dbusers.Command_GET_AllUsers(db)
		allClients, _ := dbclients.Command_GET_AllClients(db)
		allPerms, _ := dbpermission.Command_GET_AllUserPermissions(db)
		allClientPerms, _ := dbpermission.Command_GET_AllClientPermissions(db)
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

		// Exigence de second facteur, relue après les actions pour que le réglage
		// qui vient d'être posé s'affiche sans recharger la page.
		_ = db.QueryRow(`SELECT mfa_required FROM groups WHERE group_name = ?`,
			detailGroup).Scan(&detailData.MFARequired)

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
		// Le formulaire de cette page nomme le groupe « group_name » ; l'action
		// attend « group ». L'alias est posé ici plutôt que dans la table
		// globale : « group_name » ne désigne un groupe QUE sur cette page, et
		// un alias global le ferait aussi valoir ailleurs, où le champ pourrait
		// avoir un autre sens.
		res, traite, err := ExecuterActionFormulaireAvec(r, username, groupIDs,
			act.Params{"group": r.FormValue("group_name")})
		if traite {
			if err != nil {
				data.Message = MessageDActionPourAffichage(res, err)
			} else {
				data.Message = res.Message
			}
		}
	}
	groups, err := dbgroups.Command_GET_GroupDetails(db)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeWebAdmin, "webadmin: list groups failed: "+err.Error())
		http.Error(w, "Erreur liste groupes", http.StatusInternalServerError)
		return
	}
	scope := newDomainScope(groupIDs, "read:get:group")
	filteredGroups := filterGroups(scope, groups)
	logScopeFiltering(username, "groupes", len(groups), len(filteredGroups))
	data.Groups = filteredGroups
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
		client, err := dbclients.Command_GET_ClientByComputeurID(db, detailClient)
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
			// Le contrôle des droits et l'effet vivent dans les actions
			// client.update et client.delete. La table « action → clé RBAC »
			// qui vivait ici a disparu avec le `if actionKey != ""` qui la
			// suivait — ce motif sautait la vérification pour toute action
			// absente de la table.
			//
			// La cible vient de l'URL quand le formulaire ne la répète pas.
			res, traite, err := ExecuterActionFormulaireAvec(r, username, groupIDs,
				act.Params{"computeur_id": detailClient})

			if traite {
				if err != nil {
					detailData.Message = MessageDActionPourAffichage(res, err)
				} else {
					detailData.Message = res.Message

					// La suppression renvoie vers la liste : la page de détail
					// afficherait une machine qui n'existe plus.
					if r.FormValue("action") == "delete_client" {
						http.Redirect(w, r, "/admin/clients", http.StatusSeeOther)
						return
					}
					// Relecture après mise à jour : la page doit montrer ce qui
					// est en base, pas ce qui vient d'être posté.
					if maj, ok := res.Donnees.(*storage.Software); ok && maj != nil {
						detailData.Client = maj
					}
				}
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
		// Les actions client.create et client.delete portent leur clé RBAC.
		//
		// Le type n'est pas saisi : ce formulaire ne crée qu'un client basic.
		// Un client service s'enrôle lui-même avec sa propre paire de clés — sa
		// clé privée ne doit jamais quitter l'hôte qui l'utilisera.
		res, traite, err := ExecuterActionFormulaire(r, username, groupIDs)
		if traite {
			if err != nil {
				data.Message = MessageDActionPourAffichage(res, err)
			} else {
				data.Message = res.Message
			}
		}
	}
	clients, err := dbclients.Command_GET_AllClients(db)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeWebAdmin, "webadmin: list clients failed: "+err.Error())
		http.Error(w, "Erreur liste clients", http.StatusInternalServerError)
		return
	}
	scope := newDomainScope(groupIDs, "read:get:client")
	filteredClients := filterClients(scope, clients)
	logScopeFiltering(username, "clients", len(clients), len(filteredClients))
	data.Clients = filteredClients
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
		perm, err := dbpermission.Command_GET_UserPermissionByName(db, detailPerm)
		if err != nil || perm == nil {
			http.Error(w, "Permission introuvable", http.StatusNotFound)
			return
		}
		groups, _ := dbpermission.Command_GET_Groups_ByUserPermission(db, detailPerm)
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
			// La suppression passe par le registre. La modification des
			// actions RBAC — « update_permission_action » ci-dessous — n'y
			// passe PAS : elle manipule la grammaire interne des permissions
			// (nil / all / ajout ou retrait d'un domaine avec propagation),
			// qui mérite ses propres actions plutôt qu'une traduction hâtive.
			// C'est le pendant de « update -pu » côté ligne de commande.
			//
			// Son contrôle de droits reste donc ici, sur les domaines de la
			// permission — ceux des groupes qui la portent, puisque la modifier
			// change les droits dans tous ces domaines à la fois.
			if action == "delete_permission" {
				// La confirmation par ressaisie du nom est conservée : supprimer
				// une permission retire des droits à tous les groupes qui la
				// portent, d'un coup et sans retour.
				if r.FormValue("target_perm") != detailPerm {
					detailData.Error = "Suppression : saisissez exactement le nom de la permission pour confirmer."
				} else {
					res, traite, errAction := ExecuterActionFormulaireAvec(r, username, groupIDs,
						act.Params{"permission_name": detailPerm})
					if traite {
						if errAction != nil {
							detailData.Error = MessageDActionPourAffichage(res, errAction)
						} else {
							http.Redirect(w, r, "/admin/permissions", http.StatusSeeOther)
							return
						}
					}
				}
				action = ""
			}

			if action == "update_permission_action" {
				domains := entityDomainsOrGlobal(permission.GetDomainslistFromUserpermission(detailPerm))
				if allowed, reason := checkWebAdminRBACOnDomains(groupIDs, "write:update:permission", domains); !allowed {
					logs.Write_Log("SECURITY", fmt.Sprintf(
						"webadmin: %s tente %s sur la permission %s — %s", username, action, detailPerm, reason))
					detailData.Error = "Permission refusée : " + reason
					action = ""
				}
			}

			switch action {
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

				permID, errID := dbpermission.Command_GET_UserPermissionID(db, detailPerm)
				if errID != nil {
					detailData.Error = "Permission introuvable."
					break
				}
				current, errGet := dbpermission.Command_GET_UserPermissionAction(db, permID, field)
				if errGet != nil {
					detailData.Error = "Erreur lecture action: " + errGet.Error()
					break
				}
				parsed := permission.ParsePermissionAction(current)
				switch op {
				case "nil":
					if err := dbpermission.Command_SET_UserPermissionAction(db, permID, field, "nil"); err != nil {
						detailData.Error = "Erreur: " + err.Error()
					} else {
						detailData.Message = "Action " + field + " mise à nil."
					}
				case "all":
					if err := dbpermission.Command_SET_UserPermissionAction(db, permID, field, "all"); err != nil {
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
					if err := dbpermission.Command_SET_UserPermissionAction(db, permID, field, newVal); err != nil {
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
					if err := dbpermission.Command_SET_UserPermissionAction(db, permID, field, newVal); err != nil {
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
				if reloaded, reloadErr := dbpermission.Command_GET_UserPermissionByName(db, detailPerm); reloadErr == nil && reloaded != nil {
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
		data.ActiveTab = sanitizeTabFrom(r.FormValue("active_tab"), permissionListTabs)
		// Les cinq actions de cette page passent par le registre.
		//
		// Elles portent leur clé RBAC et journalisent en SECURITY les deux
		// réglages qui accordent un privilège : « web_admin » sur une
		// permission utilisateur ouvre l'administration, « is_admin » sur une
		// permission client donne les droits d'administration aux machines du
		// groupe qui la porte.
		//
		// Les messages nomment désormais cette conséquence — c'est le moment où
		// l'on peut encore revenir en arrière sans avoir rien cassé.
		//
		// Deux « break » silencieux ont disparu : update_client_permission et
		// delete_client_permission ne faisaient rien, sans un mot, quand le nom
		// était vide.
		res, traite, errAction := ExecuterActionFormulaire(r, username, groupIDs)
		if traite {
			if errAction != nil {
				data.Error = MessageDActionPourAffichage(res, errAction)
			} else {
				data.Message = res.Message
			}
		}
	}

	perms, err := dbpermission.Command_GET_AllUserPermissions(db)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeWebAdmin, "webadmin: list permissions failed: "+err.Error())
		http.Error(w, "Erreur liste permissions", http.StatusInternalServerError)
		return
	}
	scope := newDomainScope(groupIDs, "read:get:permission")
	filteredPerms := filterUserPermissions(scope, perms)
	logScopeFiltering(username, "permissions", len(perms), len(filteredPerms))
	data.Perms = filteredPerms

	// L'échec de lecture des permissions client n'empêche pas d'afficher les
	// permissions utilisateur : la page reste utile, et le bandeau d'erreur
	// signale ce qui manque plutôt que de renvoyer une page blanche.
	clientPerms, err := dbpermission.Command_GET_AllClientPermissions(db)
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
	// requireWebAdminWithGroupIDs et non requireWebAdmin : les actions sur les
	// certificats exigent l'appartenance au groupe protégé, laquelle se lit
	// dans les groupes de l'appelant. Sans eux, le registre n'a rien à
	// examiner.
	username, groupIDs, ok := requireWebAdminWithGroupIDs(w, r)
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
		cert, err := dbcertificates.GetCertificateByID(certID)
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
			// L'action certificate.delete exige l'appartenance au groupe
			// protégé — un certificat ne porte aucun domaine, donc aucune clé
			// RBAC ne le couvre. Elle journalise aussi la suppression.
			//
			// L'identifiant vient de l'URL : le formulaire de détail ne le
			// répète pas.
			res, traite, err := ExecuterActionFormulaireAvec(r, username, groupIDs,
				act.Params{"certificate_id": strconv.Itoa(certID)})
			if traite {
				if err != nil {
					detailData.Message = MessageDActionPourAffichage(res, err)
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
		// L'analyse de l'identifiant, le contrôle d'appartenance et la trace
		// vivent dans l'action certificate.delete.
		res, traite, err := ExecuterActionFormulaire(r, username, groupIDs)
		if traite {
			if err != nil {
				data.Message = MessageDActionPourAffichage(res, err)
			} else {
				data.Message = res.Message
			}
		}
	}

	certificates, err := dbcertificates.GetAllCertificates()
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
// Access: web_admin + read:log. Les journaux couvrent tous les domaines, ils ne
// se rattachent donc à aucun droit de lecture par entité.
func AdminLogsHandler(w http.ResponseWriter, r *http.Request) {
	username, groupIDs, ok := requireWebAdminWithGroupIDs(w, r)
	if !ok {
		return
	}
	// read:log, et non read:get:user comme auparavant.
	//
	// Les journaux ne se filtrent pas par domaine : une ligne de journal n'en
	// porte pas. Les adosser au droit de lire les utilisateurs revenait donc à
	// donner l'activité de TOUT le parc — tentatives d'authentification, refus
	// de permission, déclenchements de kill switch — à quiconque pouvait
	// consulter un annuaire, fût-ce sur un seul domaine.
	if !checkWebAdminRBAC(w, r, groupIDs, permission.ActionReadLog) {
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
// Access: web_admin + read:log, revérifié ici et pas seulement sur la page.
func AdminLogsAPIHandler(w http.ResponseWriter, r *http.Request) {
	username, groupIDs, ok := requireWebAdminWithGroupIDs(w, r)
	if !ok {
		http.Error(w, "Non autorisé", http.StatusUnauthorized)
		return
	}
	// Même droit que la page, vérifié séparément : l'API est appelée
	// directement par le navigateur et doit se défendre seule. S'en remettre au
	// contrôle de la page laisserait l'endpoint ouvert à qui connaît son URL.
	if !permission.HasActionAnywhere(groupIDs, permission.ActionReadLog) {
		logs.Write_Log("SECURITY", "webadmin: "+username+" tente de lire les journaux sans le droit "+permission.ActionReadLog)
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
