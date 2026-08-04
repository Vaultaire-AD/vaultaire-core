package webserveur

import (
	"html/template"
	"net/http"
	"strings"
	"vaultaire/core/command"
	"vaultaire/core/database"
	dbcertificates "vaultaire/core/database/db_certificates"
	isprotected "vaultaire/core/database/is_protected"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
	"vaultaire/core/storage"
	duckykey "vaultaire/ducky-network/key_management"
)

const adminTplDir = "web_packet/sso_WEB_page/templates"

// executeAdminPage parse le partial sidebar + la page et exécute la page (sidebar commun à toutes les pages admin).
func executeAdminPage(w http.ResponseWriter, pageName string, data interface{}) error {
	tmpl, err := template.ParseFiles(adminTplDir+"/admin_sidebar.html", adminTplDir+"/"+pageName)
	if err != nil {
		return err
	}
	return tmpl.ExecuteTemplate(w, pageName, data)
}

// requireWebAdmin checks session and web_admin permission; if not allowed, redirects to / or /profil and returns false.
func requireWebAdmin(w http.ResponseWriter, r *http.Request) (username string, ok bool) {
	// La validation du jeton ET la restriction « mot de passe expiré » sont dans
	// requireLogin : aucune page d'administration ne doit être atteignable avec
	// un mot de passe expiré, et le contrôle ne doit exister qu'à un seul endroit.
	username, _, ok = requireLogin(w, r, false)
	if !ok {
		return "", false
	}
	groupIDs, action, err := permission.PrePermissionCheck(username, "web_admin")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return "", false
	}
	allowed, _ := permission.CheckPermissionsMultipleDomains(groupIDs, action, []string{"*"})
	if !allowed {
		http.Redirect(w, r, "/profil", http.StatusSeeOther)
		return "", false
	}
	return username, true
}

// requireWebAdminWithGroupIDs does requireWebAdmin then returns the user's groupIDs (same as command package uses for RBAC).
// Use with permission.CheckPermissionsMultipleDomains(groupIDs, actionKey, domains) for entity-specific checks.
func requireWebAdminWithGroupIDs(w http.ResponseWriter, r *http.Request) (username string, groupIDs []int, ok bool) {
	username, ok = requireWebAdmin(w, r)
	if !ok {
		return "", nil, false
	}
	groupIDs, err := permission.GetGroupIDsForUser(username)
	if err != nil {
		http.Redirect(w, r, "/profil", http.StatusSeeOther)
		return "", nil, false
	}
	return username, groupIDs, true
}

// Deux contrôles distincts, et les confondre était le défaut de l'interface.
//
// `web_admin` est la porte d'entrée : sans lui, aucune page d'administration.
// Il est global par nature (voir permission.IsGlobalOnlyAction) et vérifié une
// fois par requireWebAdmin.
//
// Ensuite viennent les droits RBAC, exactement comme en ligne de commande où
// `web_admin` n'entre jamais en jeu. Mais l'interface les vérifiait toujours
// contre « * », c'est-à-dire en exigeant le droit global : un administrateur
// délégué sur un domaine se retrouvait capable de tout faire en CLI et de rien
// faire en web. La séparation ci-dessous corrige ça :
//
//   - checkWebAdminRBAC          : « as-tu quelque chose à faire sur cette
//     page ? » — le droit sur au moins un domaine suffit à l'ouvrir ;
//   - checkWebAdminRBACOnDomains : « as-tu le droit sur CETTE entité ? » — le
//     droit est exigé sur chacun de ses domaines, comme en CLI.
//
// Ouvrir une page ne donne donc aucun pouvoir : chaque action reste contrôlée
// sur sa cible.

// checkWebAdminRBAC autorise l'accès à une page dès lors que l'action est
// accordée quelque part. Redirige vers /profil sinon.
func checkWebAdminRBAC(w http.ResponseWriter, r *http.Request, groupIDs []int, actionKey string) bool {
	if !permission.HasActionAnywhere(groupIDs, actionKey) {
		http.Redirect(w, r, "/profil", http.StatusSeeOther)
		return false
	}
	return true
}

// checkWebAdminRBACOnDomains vérifie une action sur les domaines d'une entité
// précise. Ne redirige pas : l'appelant affiche le refus dans la page, pour que
// l'administrateur comprenne quel droit lui manque au lieu d'être renvoyé sans
// explication.
func checkWebAdminRBACOnDomains(groupIDs []int, actionKey string, domains []string) (bool, string) {
	return permission.CheckPermissionsAllDomains(groupIDs, actionKey, domains)
}

// canDeleteCertificate réserve la suppression d'un certificat aux membres du
// groupe superadmin.
//
// Les certificats ne sont pas des entités d'annuaire : ils ne portent pas de
// domaine, donc aucune clé RBAC ne les couvre et aucune délégation ne peut s'y
// appliquer proprement. Or supprimer le certificat TLS de l'API ou de LDAPS
// interrompt le service pour tout le monde, sans rapport avec un périmètre
// délégué. L'appartenance au groupe vaultaire est le bon niveau : c'est déjà
// celui des restrictions GPO, pour la même raison — un réglage qui engage tout
// le parc n'appartient à aucun domaine en particulier.
func canDeleteCertificate(username string) bool {
	if !isprotected.IsSuperadmin(database.GetDatabase(), username) {
		logs.Write_Log("SECURITY",
			"webadmin: "+username+" a tenté de supprimer un certificat sans être membre du groupe "+
				isprotected.ProtectedGroupName)
		return false
	}
	return true
}

// entityDomainsOrGlobal réduit une erreur de résolution de domaines à un refus.
//
// Ne pas savoir à quels domaines appartient une entité n'autorise rien : la
// liste vide fait exiger le droit global par CheckPermissionsAllDomains. Une
// panne de lecture ne doit pas élargir les droits.
func entityDomainsOrGlobal(domains []string, err error) []string {
	if err != nil || len(domains) == 0 {
		return nil
	}
	return domains
}

// AdminIndexHandler serves the admin dashboard and executes CLI-style commands via POST.
func AdminIndexHandler(w http.ResponseWriter, r *http.Request) {
	username, ok := requireWebAdmin(w, r)
	if !ok {
		return
	}

	data := struct {
		Username                string
		Output                  string
		DnsEnable               bool
		Section                 string
		Debug                   bool
		LoginClientPublicKey    string
		LoginClientAddKeyScript string
	}{Username: username, DnsEnable: storage.Dns_Enable, Section: "dashboard", Debug: storage.Debug}

	// Load login client public key for "client -join" copy-paste
	if cert, err := dbcertificates.GetCertificateByName(duckykey.ServerLoginClientKeyName); err == nil && cert.PublicKeyData != nil {
		pub := strings.TrimSpace(*cert.PublicKeyData)
		data.LoginClientPublicKey = pub
		// Escape single quotes for use inside shell '...'
		pubEsc := strings.ReplaceAll(pub, "'", "'\"'\"'")
		data.LoginClientAddKeyScript = "#!/bin/sh\n# Add Vaultaire server public key to root@client (for client -join)\n# Run as root on the client machine.\nmkdir -p /root/.ssh\necho '" + pubEsc + "' >> /root/.ssh/authorized_keys\nchmod 700 /root/.ssh\nchmod 600 /root/.ssh/authorized_keys\n"
	}

	if r.Method == http.MethodPost {
		if r.FormValue("action") == "set_debug" {
			storage.Debug = r.FormValue("debug") == "on" || r.FormValue("debug") == "1"
		} else {
			cmd := strings.TrimSpace(r.FormValue("command"))
			if cmd != "" {
				data.Output = command.ExecuteCommand(cmd, username)
			}
		}
		data.Debug = storage.Debug
	}

	if err := executeAdminPage(w, "admin.html", data); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeWebTemplate, "admin template: "+err.Error())
		http.Error(w, "Template manquant", http.StatusInternalServerError)
	}
}
