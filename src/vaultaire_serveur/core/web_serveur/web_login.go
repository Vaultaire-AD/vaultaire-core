package webserveur

import (
	"fmt"
	"net/http"
	"time"
	"vaultaire/core/auth/ratelimit"
	"vaultaire/core/database"
	dbusers "vaultaire/core/database/db_users"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
	"vaultaire/core/web_serveur/session"
)

func LoginPageHandler(w http.ResponseWriter, r *http.Request) {
	err := rendreGabarit(w, templates, nil)
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
	source := ratelimit.SourceHTTP(r)

	// LIMITATION DES TENTATIVES — avant tout le reste.
	//
	// Placée ici, et non après la recherche du compte, pour deux raisons : un
	// balayage de noms d'utilisateur interrogerait sinon la base à chaque essai,
	// et le temps de réponse distinguerait le compte existant de l'inconnu.
	//
	// La redirection est la MÊME que celle des autres échecs. Répondre « trop de
	// tentatives » dirait à l'attaquant qu'il a touché un compte réel et qu'il
	// lui suffit d'espacer ses essais ; le journal serveur, lui, porte la vraie
	// raison.
	//
	// Les compteurs sont partagés avec le bind LDAP et le canal Ducky : sans
	// cela, qui est freiné sur une porte recommence sur la suivante.
	if autorisé, reste := ratelimit.Autorise(username, source); !autorisé {
		logs.Write_LogCode("SECURITY", logs.CodeAuthLoginDenied, fmt.Sprintf(
			"connexion web: trop de tentatives depuis %s pour %s, encore %s",
			source, username, reste.Round(time.Second)))
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// KILL SWITCH — avant toute lecture du mot de passe, et avec la même
	// redirection muette que les autres échecs : la page de connexion ne doit
	// pas distinguer un compte révoqué d'un mot de passe faux.
	if permission.IsRevoked(username) {
		logs.Write_LogCode("SECURITY", logs.CodeAuthLoginDenied,
			"Tentative de connexion web sur le compte révoqué "+username)
		ratelimit.Echec(username, source)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	db := database.GetDatabase()
	userID, err := dbusers.Get_User_ID_By_Username(db, username)
	if err != nil {
		// Tentative de connexion avec un username inconnu : pas une erreur système,
		// mais un événement de sécurité qu'on veut voir sans activer le mode debug.
		logs.Write_LogCode("WARNING", logs.CodeAuthLoginDenied, "Tentative de connexion avec un utilisateur invalide : "+username)
		ratelimit.Echec(username, source)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	valide, err := dbusers.VerifierMotDePasse(db, userID, password)
	if err != nil {
		// Ici l'utilisateur existe : un échec à ce stade est un vrai problème DB, pas
		// juste un mauvais mot de passe.
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "Erreur récupération mot de passe pour "+username+" : "+err.Error())
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if !valide {
		logs.Write_LogCode("WARNING", logs.CodeAuthLoginDenied, "Mauvais mot de passe pour "+username)
		ratelimit.Echec(username, source)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Compteurs remis à zéro dès que le mot de passe est prouvé, et non après le
	// second facteur : la limitation protège le MOT DE PASSE. Attendre le code
	// ferait accumuler des échecs à qui se trompe de code alors qu'il a déjà
	// démontré son identité, et l'enfermerait dehors avec le bon secret en main.
	ratelimit.Reussite(username, source)

	// ✅ Mot de passe correct — le reste du parcours est dans web_login_mfa.go.
	//
	// Aucun cookie de session n'est posé ici. Le second facteur, quand il est
	// actif, s'intercale entre ce point et l'ouverture de session : poser le
	// cookie maintenant puis « exiger » le code ensuite reviendrait à donner la
	// session d'abord et à demander la preuve après, c'est-à-dire à n'avoir
	// aucun second facteur pour qui ignore la redirection.
	//
	// startSecondFactor écrit la réponse dans tous les cas et retourne true.
	startSecondFactor(w, r, username)
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
