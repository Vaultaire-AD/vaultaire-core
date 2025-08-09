package webserveur

import (
	"DUCKY/serveur/database"
	"DUCKY/serveur/logs"
	"DUCKY/serveur/storage"
	"DUCKY/serveur/web_serveur/session"
	"html/template"
	"net/http"
	"time"
)

type ProfilPageData struct {
	User storage.GetUserInfoSingle
}

func ProfilHandler(w http.ResponseWriter, r *http.Request) {
	// ✅ Authentification par token de session
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

	db := database.GetDatabase()
	userInfo, err := database.Command_GET_UserInfo(db, username)
	if err != nil {
		http.Error(w, "Erreur récupération infos utilisateur", 500)
		return
	}

	if r.Method == "GET" {
		tmpl, err := template.ParseFiles("web_packet/sso_WEB_page/templates/profil.html")
		if err != nil {
			http.Error(w, "Template manquant", 500)
			return
		}
		err = tmpl.Execute(w, ProfilPageData{User: *userInfo})
		if err != nil {
			logs.Write_Log("ERROR", "Erreur lors de l'exécution du template de la page profil : "+err.Error())
			http.Error(w, "Erreur lors de l'exécution du template", 500)
		}
		return
	}

	// ✅ Méthode POST : traitement mise à jour
	newUsername := r.FormValue("username")
	firstname := r.FormValue("firstname")
	lastname := r.FormValue("lastname")
	password := r.FormValue("password")
	confirm := r.FormValue("confirm_password")

	// Vérif mot de passe
	if password != "" && password != confirm {
		http.Error(w, "Mot de passe non confirmé", 400)
		return
	}

	// 🔐 On récupère l'username à partir du token pour sécuriser
	cookie, err := r.Cookie("session_token")
	if err != nil || cookie.Value == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	currentUsername, valid := session.ValidateToken(cookie.Value)
	if !valid {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Obtenir l'ID utilisateur
	userID, err := database.Get_User_ID_By_Username(db, currentUsername)
	if err != nil {
		http.Error(w, "Utilisateur introuvable", 500)
		return
	}

	// 🎯 MAJ en base
	err = database.Update_User_Info(db, userID, newUsername, firstname, lastname, password, "") // birthdate vide pour l'instant
	if err != nil {
		http.Error(w, "Erreur mise à jour: "+err.Error(), 500)
		return
	}

	// ✅ Si username a changé : mettre à jour le token
	if newUsername != currentUsername {
		newToken := session.CreateSession(newUsername)

		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    newToken,
			HttpOnly: true,
			Secure:   true,
			Path:     "/",
			Expires:  time.Now().Add(30 * time.Minute),
		})
	}

	http.Redirect(w, r, "/profil", http.StatusSeeOther)

}
