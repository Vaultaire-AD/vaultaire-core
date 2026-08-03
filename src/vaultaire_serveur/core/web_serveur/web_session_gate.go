package webserveur

import (
	"net/http"

	"vaultaire/core/web_serveur/session"
)

// Portillon commun à toutes les pages authentifiées.
//
// POURQUOI UNE FONCTION ET PAS UN CONTRÔLE RECOPIÉ. Chaque handler validait son
// jeton lui-même, en trois lignes identiques. Ajouter une condition — ici, le
// mot de passe expiré — obligerait à la recopier dans chacun, et le prochain
// handler écrit l'oublierait. Un compte au mot de passe expiré atteindrait
// alors la page oubliée, ce qui viderait la restriction de son sens : il suffit
// d'UNE page accessible pour que le blocage ne bloque rien.
//
// Les deux portes d'entrée du site — requireWebAdmin pour /admin/*, ProfilHandler
// pour /profil — passent désormais par ici.

// requireLogin valide la session et applique la restriction de mot de passe.
//
// `allowPasswordChange` doit être vrai UNIQUEMENT sur la page qui permet de
// changer son mot de passe. Partout ailleurs, une session marquée est renvoyée
// vers elle. Sans cette exception, la redirection pointerait vers une page
// elle-même redirigée : une boucle dont l'utilisateur ne sortirait pas.
func requireLogin(w http.ResponseWriter, r *http.Request, allowPasswordChange bool) (username, token string, ok bool) {
	cookie, err := r.Cookie("session_token")
	if err != nil || cookie.Value == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return "", "", false
	}
	username, valid := session.ValidateToken(cookie.Value)
	if !valid {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return "", "", false
	}
	if !allowPasswordChange && session.MustChangePassword(cookie.Value) {
		http.Redirect(w, r, "/profil", http.StatusSeeOther)
		return "", "", false
	}
	return username, cookie.Value, true
}
