package webserveur

import (
	dbcert "vaultaire/serveur/database/db-certificates"
	duckykey "vaultaire/serveur/ducky-network/key_management"
	"vaultaire/serveur/command"
	"vaultaire/serveur/permission"
	"vaultaire/serveur/storage"
	"vaultaire/serveur/web_serveur/session"
	"html/template"
	"log"
	"net/http"
	"strings"
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

// requireWebAdmin checks session and web_admin permission; if not allowed, redirects to / and returns false.
func requireWebAdmin(w http.ResponseWriter, r *http.Request) (username string, ok bool) {
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

// AdminIndexHandler serves the admin dashboard and executes CLI-style commands via POST.
func AdminIndexHandler(w http.ResponseWriter, r *http.Request) {
	username, ok := requireWebAdmin(w, r)
	if !ok {
		return
	}

	data := struct {
		Username               string
		Output                 string
		DnsEnable              bool
		Section                string
		Debug                  bool
		LoginClientPublicKey   string
		LoginClientAddKeyScript string
	}{Username: username, DnsEnable: storage.Dns_Enable, Section: "dashboard", Debug: storage.Debug}

	// Load login client public key for "client -join" copy-paste
	if cert, err := dbcert.GetCertificateByName(duckykey.ServerLoginClientKeyName); err == nil && cert.PublicKeyData != nil {
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
		log.Printf("admin template: %v", err)
		http.Error(w, "Template manquant", http.StatusInternalServerError)
	}
}
