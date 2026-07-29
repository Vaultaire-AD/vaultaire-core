package webserveur

import (
	"net/http"
	"time"
	"vaultaire/core/database"
	gc "vaultaire/core/global/security"
	"vaultaire/core/logs"
	"vaultaire/core/web_serveur/session"
)

func LoginPageHandler(w http.ResponseWriter, r *http.Request) {
	err := templates.Execute(w, nil)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeWebTemplate, "Erreur lors de l'exécution du template de la page de connexion : "+err.Error())
		http.Error(w, "Erreur interne du serveur", http.StatusInternalServerError)
		return
	}
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
		// Tentative de connexion avec un username inconnu : pas une erreur système,
		// mais un événement de sécurité qu'on veut voir sans activer le mode debug.
		logs.Write_LogCode("WARNING", logs.CodeAuthLoginDenied, "Tentative de connexion avec un utilisateur invalide : "+username)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	Hpassword, salt, err := database.Get_User_Password_By_ID(db, userID)
	if err != nil {
		// Ici l'utilisateur existe : un échec à ce stade est un vrai problème DB, pas
		// juste un mauvais mot de passe.
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "Erreur récupération mot de passe pour "+username+" : "+err.Error())
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if !gc.ComparePasswords(password, salt, Hpassword) {
		logs.Write_LogCode("WARNING", logs.CodeAuthLoginDenied, "Mauvais mot de passe pour "+username)
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
