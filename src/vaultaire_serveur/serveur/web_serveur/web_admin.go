package webserveur

import (
	"DUCKY/serveur/command"
	"DUCKY/serveur/logs"
	"DUCKY/serveur/permission"
	"DUCKY/serveur/web_serveur/session"
	"html/template"
	"net/http"
	"time"
)

type AdminPageData struct {
	Username string
	Output   string
}

// AdminHandler gère l'interface d'administration web.
// Accès restreint aux utilisateurs disposant de la permission `web_admin`.
func AdminHandler(w http.ResponseWriter, r *http.Request) {
	// Auth via cookie de session
	tokenCookie, err := r.Cookie("session_token")
	if err != nil || tokenCookie.Value == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	username, valid := session.ValidateToken(tokenCookie.Value)
	if !valid {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Vérification des permissions web_admin
	groupsID, action, err := permission.PrePermissionCheck(username, "web_admin")
	if err != nil {
		logs.Write_Log("WARNING", "PrePermissionCheck échoué pour user "+username+": "+err.Error())
		http.Error(w, "Permission refusée", http.StatusForbidden)
		return
	}

	ok, reason := permission.CheckPermissionsMultipleDomains(groupsID, action, []string{"*"})
	if !ok {
		logs.Write_Log("WARNING", "Accès admin refusé pour "+username+" : "+reason)
		http.Error(w, "Accès admin refusé : "+reason, http.StatusForbidden)
		return
	}

	// Méthode POST : exécuter une commande côté serveur via l'interface
	output := ""
	if r.Method == "POST" {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Données invalides", http.StatusBadRequest)
			return
		}
		cmd := r.FormValue("command")
		if cmd != "" {
			// Exécuter la commande en tant qu'utilisateur connecté
			output = command.ExecuteCommand(cmd, username)
		}
		// Petite mise à jour de la session pour prolonger
		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    tokenCookie.Value,
			HttpOnly: true,
			Secure:   true,
			Path:     "/",
			Expires:  time.Now().Add(30 * time.Minute),
		})
	}

	// Render template
	tmpl, err := template.ParseFiles("web_packet/sso_WEB_page/templates/admin.html")
	if err != nil {
		logs.Write_Log("ERROR", "Template admin manquant: "+err.Error())
		http.Error(w, "Template admin manquant", http.StatusInternalServerError)
		return
	}

	data := AdminPageData{Username: username, Output: output}
	if err := tmpl.Execute(w, data); err != nil {
		logs.Write_Log("ERROR", "Erreur execution template admin: "+err.Error())
		http.Error(w, "Erreur interne", http.StatusInternalServerError)
		return
	}

}
