package webserveur

import (
	"DUCKY/serveur/authentification/client"
	"DUCKY/serveur/database"
	"DUCKY/serveur/web_serveur/session"
	"log"
	"net/http"
	"time"
)

func LoginPageHandler(w http.ResponseWriter, r *http.Request) {
	templates.Execute(w, nil)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	db := database.GetDatabase()
	userID, err := database.Get_User_ID_By_Username(db, username)
	if err != nil {
		log.Printf("⚠️ Utilisateur invalide : %s", username)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	Hpassword, salt, err := database.Get_User_Password_By_ID(db, userID)
	if err != nil {
		log.Printf("⚠️ Erreur récupération mot de passe : %s", username)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if !client.ComparePasswords(password, salt, Hpassword) {
		log.Printf("❌ Mauvais mot de passe pour %s", username)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// ✅ Création d'un token sécurisé
	token := session.CreateSession(username)

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    token,
		HttpOnly: true,
		Secure:   true, // HTTPS requis
		Path:     "/",
		Expires:  time.Now().Add(30 * time.Minute),
	})

	http.Redirect(w, r, "/profil", http.StatusSeeOther)
}
