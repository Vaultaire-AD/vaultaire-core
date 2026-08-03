package webserveur

import (
	"html/template"
	"net/http"
	"time"

	"vaultaire/core/auth/passwordpolicy"
	"vaultaire/core/database"
	dbauthpolicy "vaultaire/core/database/db_authpolicy"
	"vaultaire/core/global/security/totp"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
	"vaultaire/core/web_serveur/session"
)

// Étape du second facteur, entre le mot de passe et l'ouverture de session.
//
// ORDRE DES CONTRÔLES, et il n'est pas interchangeable :
//
//	1. mot de passe          (web_login.go)
//	2. second facteur        (ici)
//	3. expiration du mot de passe
//
// L'expiration vient EN DERNIER. La placer avant le second facteur permettrait
// à qui détient un mot de passe volé d'apprendre qu'il est expiré sans avoir
// franchi le second facteur — soit un oracle sur l'état d'un compte, offert
// précisément à celui contre qui le second facteur protège. En dernier, le
// message n'atteint que quelqu'un qui a déjà tout prouvé.

const mfaPendingCookie = "mfa_pending"

// mfaTemplatePath est la page de saisie du code.
var mfaTemplatePath = adminTplDir + "/login_mfa.html"

// startSecondFactor décide de la suite après un mot de passe valide.
//
// Trois issues :
//   - second facteur actif        → étape intermédiaire, page de saisie du code ;
//   - second facteur exigé mais pas encore posé → session ouverte, mais
//     enfermée sur la page d'enrôlement ;
//   - rien d'exigé                → session ordinaire.
//
// Retourne true quand la réponse HTTP a été écrite et que l'appelant doit
// s'arrêter là.
func startSecondFactor(w http.ResponseWriter, r *http.Request, username string) bool {
	db := database.GetDatabase()

	state, err := dbauthpolicy.GetAuthState(db, username)
	if err != nil {
		// Le compte a disparu entre la vérification du mot de passe et cette
		// lecture — un kill switch en mode hard, typiquement. On refuse, avec la
		// même redirection muette que les autres échecs.
		logs.Write_LogCode("ERROR", logs.CodeWebSession,
			"login: état d'authentification illisible pour "+username+" : "+err.Error())
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return true
	}

	if state.MFAEnabled && state.MFASecret != "" {
		token := session.CreatePending(username)
		if token == "" {
			logs.Write_LogCode("ERROR", logs.CodeWebSession,
				"login: étape de second facteur non créée pour "+username)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return true
		}
		setPendingCookie(w, token)
		http.Redirect(w, r, "/login/mfa", http.StatusSeeOther)
		return true
	}

	// Exigé par un groupe mais pas encore enrôlé. On ouvre une session — sinon
	// l'utilisateur n'aurait aucun moyen d'atteindre la page d'enrôlement — mais
	// la fonction d'enrôlement forcé la restreint à cette seule page.
	required, err := dbauthpolicy.IsMFARequired(db, username)
	if err != nil {
		// IsMFARequired est fail-closed : en cas d'erreur elle répond « exigé ».
		// On suit sa réponse et on journalise, plutôt que de passer outre.
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"login: exigence MFA illisible pour "+username+" : "+err.Error())
	}
	if required {
		logs.Write_Log("INFO", "login: "+username+" doit enrôler un second facteur avant d'accéder à l'interface")
	}

	return finishLogin(w, r, username, required)
}

// finishLogin ouvre la session définitive et applique l'expiration.
//
// `mustEnrollMFA` enferme sur la page d'enrôlement, `MustChangePassword` sur la
// page de mot de passe. Les deux peuvent être vrais : la redirection donne alors
// la priorité au mot de passe, parce qu'un mot de passe expiré bloque déjà LDAP
// et Ducky, alors qu'un second facteur manquant ne bloque que l'interface.
func finishLogin(w http.ResponseWriter, r *http.Request, username string, mustEnrollMFA bool) bool {
	status := passwordpolicy.Status{State: passwordpolicy.StateValid}
	if st, err := passwordpolicy.Check(database.GetDatabase(), username); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"login: état d'expiration illisible pour "+username+" ("+err.Error()+") — connexion autorisée")
	} else {
		status = st
	}

	token := session.CreateSessionWithConstraint(username, status.IsExpired())
	if token == "" {
		logs.Write_LogCode("ERROR", logs.CodeWebSession, "Session non créée pour "+username)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return true
	}
	setSessionCookie(w, token)

	switch {
	case status.IsExpired():
		logs.Write_Log("SECURITY", "login: "+username+" connecté avec un mot de passe expiré, accès restreint au changement")
		http.Redirect(w, r, "/profil", http.StatusSeeOther)
	case mustEnrollMFA:
		http.Redirect(w, r, "/profil/mfa", http.StatusSeeOther)
	default:
		http.Redirect(w, r, "/profil", http.StatusSeeOther)
	}
	return true
}

// MFAPageHandler affiche la saisie du code et traite sa soumission.
func MFAPageHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(mfaPendingCookie)
	if err != nil || cookie.Value == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	username, ok := session.PendingUsername(cookie.Value)
	if !ok {
		clearPendingCookie(w)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if r.Method != http.MethodPost {
		renderMFAPage(w, "")
		return
	}

	// Le compte a pu être révoqué pendant que l'utilisateur cherchait son
	// téléphone. Le kill switch efface les étapes en cours, mais la vérification
	// ici couvre aussi une révocation arrivée entre-temps par un autre chemin.
	if permission.IsRevoked(username) {
		session.DeletePending(cookie.Value)
		clearPendingCookie(w)
		logs.Write_LogCode("SECURITY", logs.CodeAuthLoginDenied,
			"login: second facteur présenté sur le compte révoqué "+username)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	state, err := dbauthpolicy.GetAuthState(database.GetDatabase(), username)
	if err != nil || !state.MFAEnabled || state.MFASecret == "" {
		session.DeletePending(cookie.Value)
		clearPendingCookie(w)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	counter, valid := totp.Validate(state.MFASecret, r.FormValue("code"), time.Now())
	if !valid {
		logs.Write_LogCode("WARNING", logs.CodeAuthLoginDenied, "login: code de second facteur invalide pour "+username)
		if !session.RegisterFailedMFA(cookie.Value) {
			clearPendingCookie(w)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		renderMFAPage(w, "Code invalide.")
		return
	}

	// ANTI-REJEU. Un code reste affiché trente secondes et la fenêtre de
	// tolérance en accepte quatre-vingt-dix : sans cette consommation, un code
	// observé par-dessus l'épaule, ou lu dans un journal mal configuré, servirait
	// une seconde fois. La condition est portée par la requête SQL, donc deux
	// tentatives simultanées ne peuvent pas réussir toutes les deux.
	consumed, err := dbauthpolicy.ConsumeMFACounter(database.GetDatabase(), username, counter)
	if err != nil {
		renderMFAPage(w, "Erreur interne, réessayez.")
		return
	}
	if !consumed {
		logs.Write_LogCode("SECURITY", logs.CodeAuthLoginDenied,
			"login: code de second facteur rejoué pour "+username)
		if !session.RegisterFailedMFA(cookie.Value) {
			clearPendingCookie(w)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		renderMFAPage(w, "Ce code a déjà été utilisé, attendez le suivant.")
		return
	}

	session.DeletePending(cookie.Value)
	clearPendingCookie(w)
	logs.Write_Log("INFO", "login: second facteur validé pour "+username)
	finishLogin(w, r, username, false)
}

// renderMFAPage affiche la page de saisie.
//
// Le template est relu à chaque appel, comme le fait executeAdminPage : le
// projet ne pré-compile que la page de connexion, et introduire ici un cache que
// les autres pages n'ont pas créerait une incohérence de rechargement en
// développement.
func renderMFAPage(w http.ResponseWriter, errMsg string) {
	tmpl, err := template.ParseFiles(mfaTemplatePath)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeWebTemplate, "login: template MFA illisible : "+err.Error())
		http.Error(w, "Erreur interne du serveur", http.StatusInternalServerError)
		return
	}
	// Le nom d'utilisateur n'est volontairement PAS transmis à la page. Il
	// n'aide en rien à saisir six chiffres, et l'afficher exposerait un compte
	// valide sur un écran atteint avec un mot de passe éventuellement volé.
	if err := tmpl.Execute(w, map[string]string{"Error": errMsg}); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeWebTemplate, "login: rendu MFA échoué : "+err.Error())
	}
}

// setPendingCookie pose le cookie de l'étape intermédiaire.
//
// Mêmes attributs que le cookie de session — HttpOnly, Secure, SameSite strict —
// et une durée alignée sur celle du jeton côté serveur. Le nom diffère
// volontairement de `session_token` : les deux registres sont distincts, les
// deux cookies doivent l'être aussi, sinon une confusion d'appellation
// suffirait à franchir l'étape.
func setPendingCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     mfaPendingCookie,
		Value:    token,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		Expires:  time.Now().Add(5 * time.Minute),
	})
}

// clearPendingCookie efface le cookie de l'étape intermédiaire.
func clearPendingCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     mfaPendingCookie,
		Value:    "",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		MaxAge:   -1,
	})
}
