package webserveur

import (
	"net/http"
	"time"
	"vaultaire/core/database"
	gc "vaultaire/core/global/security"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
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

	// KILL SWITCH — avant toute lecture du mot de passe, et avec la même
	// redirection muette que les autres échecs : la page de connexion ne doit
	// pas distinguer un compte révoqué d'un mot de passe faux.
	if permission.IsRevoked(username) {
		logs.Write_LogCode("SECURITY", logs.CodeAuthLoginDenied,
			"Tentative de connexion web sur le compte révoqué "+username)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

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
	if token == "" {
		// Génération d'entropie en échec : on refuse la connexion plutôt que de
		// poser un cookie vide, qui serait ensuite validé pour n'importe qui.
		logs.Write_LogCode("ERROR", logs.CodeWebSession, "Session non créée pour "+username)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	setSessionCookie(w, token)
	http.Redirect(w, r, "/profil", http.StatusSeeOther)
}

// setSessionCookie pose le cookie de session.
//
// Centralisé : les attributs étaient recopiés à deux endroits et rien ne
// garantissait qu'ils restent identiques.
//
// SameSite=Strict est le point ajouté. Sans attribut déclaré, la protection
// dépendait entièrement du défaut du navigateur — « Lax » sur les versions
// récentes, ce qui bloque effectivement un POST inter-site, mais par la grâce du
// client et non par décision de l'application. Toutes les actions
// d'administration sont des POST simples sans jeton anti-CSRF : créer un
// utilisateur, lier une GPO, déclencher un kill switch. La déclaration explicite
// ferme le sujet quel que soit le navigateur.
func setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    token,
		HttpOnly: true,
		Secure:   true, // HTTPS requis
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		Expires:  time.Now().Add(30 * time.Minute),
	})
}

// clearSessionCookie efface le cookie de session côté navigateur.
func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		MaxAge:   -1,
	})
}

// LogoutHandler ferme la session courante.
//
// N'existait pas : le seul moyen de terminer une session était d'attendre son
// expiration. Le jeton est invalidé côté serveur ET le cookie effacé côté
// navigateur — supprimer le seul cookie laisserait le jeton valide pour qui
// l'aurait recopié.
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("session_token"); err == nil && cookie.Value != "" {
		if username, ok := session.ValidateToken(cookie.Value); ok {
			logs.Write_Log("INFO", "webadmin: déconnexion de "+username)
		}
		session.DeleteSession(cookie.Value)
	}
	clearSessionCookie(w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
