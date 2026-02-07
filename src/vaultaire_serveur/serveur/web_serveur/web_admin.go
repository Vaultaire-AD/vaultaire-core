package webserveur

import (
	"vaultaire/serveur/command"
	"vaultaire/serveur/permission"
	"vaultaire/serveur/storage"
	"vaultaire/serveur/web_serveur/session"
	"html/template"
	"log"
	"net/http"
	"strings"
)

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
		Username  string
		Output    string
		DnsEnable bool
		Section   string
	}{Username: username, DnsEnable: storage.Dns_Enable, Section: "dashboard"}

	if r.Method == http.MethodPost {
		cmd := strings.TrimSpace(r.FormValue("command"))
		if cmd != "" {
			data.Output = command.ExecuteCommand(cmd, username)
		}
	}

	tmpl, err := template.ParseFiles("web_packet/sso_WEB_page/templates/admin.html")
	if err != nil {
		log.Printf("admin template: %v", err)
		http.Error(w, "Template manquant", http.StatusInternalServerError)
		return
	}
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("admin execute: %v", err)
		http.Error(w, "Erreur serveur", http.StatusInternalServerError)
	}
}
