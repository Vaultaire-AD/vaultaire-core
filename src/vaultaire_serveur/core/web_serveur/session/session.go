package session

// 📁 vaultaire/core/webserveur/session/session.go

import (
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"sync"
	"time"

	"vaultaire/core/logs"
	"vaultaire/core/reglages"
)

type Session struct {
	Username  string
	ExpiresAt time.Time

	// MustChangePassword enferme la session sur la page de changement de mot de
	// passe.
	//
	// Posé quand le mot de passe est expiré. La session est bien réelle — le mot
	// de passe et, s'il y a lieu, le second facteur ont été vérifiés — mais elle
	// ne donne accès qu'à une seule page. C'est le seul recours laissé à
	// l'utilisateur : LDAP et Ducky/PAM refusent déjà son mot de passe, et sans
	// cette porte il faudrait un administrateur pour chaque expiration.
	//
	// L'état est porté par la session et non relu en base à chaque requête : ce
	// serait une lecture supplémentaire sur toutes les pages, pour une valeur qui
	// ne change qu'à un endroit — le changement de mot de passe, qui appelle
	// ClearMustChangePassword.
	MustChangePassword bool
}

var (
	sessions = make(map[string]Session)
	mu       sync.RWMutex

	// lastPurge borne la fréquence du nettoyage. Parcourir toute la map à
	// chaque validation de jeton ferait payer un balayage complet à chaque
	// requête, y compris aux ressources statiques.
	lastPurge time.Time
)

// duration rend la durée de vie d'une session, lue au moment où on la pose.
//
// Une VARIABLE de paquet valait 30 minutes en dur. La lire à chaque ouverture
// permet de la régler sans redémarrer le core — et c'est le réglage dont on veut
// le plus pouvoir changer d'avis, puisqu'il fixe la fenêtre pendant laquelle un
// jeton volé reste utilisable.
//
// Les sessions DÉJÀ ouvertes gardent leur échéance : elle est calculée à la
// pose, pas à la lecture. Raccourcir la durée n'écourte donc pas les sessions en
// cours. C'est le comportement le moins surprenant — l'inverse déconnecterait
// tout le monde d'un coup au moment d'un ajustement — mais il faut le savoir :
// après un incident, raccourcir la durée ne ferme rien. Pour cela il y a
// DeleteOtherSessionsOf et le kill switch.
func duration() time.Duration {
	return reglages.Duree(reglages.CleSessionWeb)
}

// purgeInterval espace les nettoyages du registre.
func purgeInterval() time.Duration {
	return reglages.Duree(reglages.CleSessionWebPurge)
}

// generateToken tire un jeton de session aléatoire.
//
// L'erreur est REMONTÉE, alors que l'ancienne version se contentait de la
// journaliser avant de retourner la valeur quand même : un tableau de zéros si
// rand.Read avait échoué, donc un jeton parfaitement prévisible. Une panne
// d'entropie doit empêcher l'ouverture de session, pas la rendre triviale à
// deviner.
func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeWebSession, "session: token generation failed: "+err.Error())
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// CreateSession ouvre une session et retourne son jeton.
//
// Retourne une chaîne vide si le jeton n'a pas pu être généré : l'appelant doit
// alors refuser la connexion plutôt que de poser un cookie vide.
func CreateSession(username string) string {
	return CreateSessionWithConstraint(username, false)
}

// CreateSessionWithConstraint ouvre une session éventuellement restreinte à la
// page de changement de mot de passe.
func CreateSessionWithConstraint(username string, mustChangePassword bool) string {
	token, err := generateToken()
	if err != nil {
		return ""
	}

	mu.Lock()
	defer mu.Unlock()
	purgeExpiredLocked()

	sessions[token] = Session{
		Username:           username,
		ExpiresAt:          time.Now().Add(duration()),
		MustChangePassword: mustChangePassword,
	}
	return token
}

// MustChangePassword dit si une session est enfermée sur le changement de mot
// de passe.
//
// Retourne false pour un jeton inconnu : l'appelant a déjà validé le jeton à ce
// stade, et répondre « oui » sur un jeton inexistant enverrait un visiteur non
// authentifié vers la page de changement plutôt que vers la connexion.
func MustChangePassword(token string) bool {
	mu.RLock()
	defer mu.RUnlock()
	s, exists := sessions[token]
	return exists && s.MustChangePassword
}

// ClearMustChangePassword lève la restriction après un changement réussi.
//
// À appeler depuis le seul endroit qui change un mot de passe. L'oublier
// laisserait l'utilisateur renvoyé vers la page de changement après avoir
// changé son mot de passe — une boucle dont il ne sortirait qu'en se
// reconnectant.
func ClearMustChangePassword(token string) {
	mu.Lock()
	defer mu.Unlock()
	if s, exists := sessions[token]; exists {
		s.MustChangePassword = false
		sessions[token] = s
	}
}

// ValidateToken vérifie un jeton et retourne le nom d'utilisateur associé.
func ValidateToken(token string) (string, bool) {
	mu.RLock()
	session, exists := sessions[token]
	mu.RUnlock()

	if !exists {
		return "", false
	}
	if session.ExpiresAt.Before(time.Now()) {
		// Retirée tout de suite plutôt que laissée jusqu'au prochain balayage :
		// elle ne sert plus à rien et continuerait d'occuper la mémoire.
		DeleteSession(token)
		return "", false
	}
	return session.Username, true
}

// DeleteSession invalide un jeton.
//
// Utilisée à la déconnexion. Sans elle, le seul moyen de fermer une session
// était d'attendre son expiration — trente minutes pendant lesquelles un poste
// laissé ouvert restait exploitable.
func DeleteSession(token string) {
	mu.Lock()
	defer mu.Unlock()
	delete(sessions, token)
}

// DeleteSessionsOf ferme toutes les sessions d'un utilisateur et retourne leur
// nombre.
//
// Appelée à la révocation d'un compte : le kill switch fermait les sessions
// Ducky mais pas les sessions web, si bien qu'un compte révoqué gardait l'accès
// à l'interface jusqu'à trente minutes. Il ne pouvait plus rien faire — ses
// permissions étaient refusées — mais il continuait de voir.
func DeleteSessionsOf(username string) int {
	mu.Lock()
	defer mu.Unlock()

	closed := 0
	for token, s := range sessions {
		if s.Username == username {
			delete(sessions, token)
			closed++
		}
	}
	return closed
}

// DeleteOtherSessionsOf ferme les sessions d'un utilisateur SAUF celle fournie.
//
// Après un changement de mot de passe réussi. Sans cela, changer son mot de
// passe n'évinçait pas celui qui avait volé le jeton, et la victime n'avait
// aucun moyen de reprendre la main. L'auteur du changement garde sa propre
// session : le déconnecter lui ferait croire que l'opération a échoué.
func DeleteOtherSessionsOf(username, keepToken string) int {
	mu.Lock()
	defer mu.Unlock()

	closed := 0
	for token, s := range sessions {
		if s.Username == username && token != keepToken {
			delete(sessions, token)
			closed++
		}
	}
	return closed
}

// RenameSessions reporte les sessions d'un utilisateur sur son nouveau nom.
//
// Un changement de nom laissait sinon les sessions pointer vers un compte
// inexistant : la page suivante échouait sur « utilisateur introuvable » sans
// que rien n'explique pourquoi.
func RenameSessions(oldUsername, newUsername string) {
	if oldUsername == newUsername {
		return
	}
	mu.Lock()
	defer mu.Unlock()

	for token, s := range sessions {
		if s.Username == oldUsername {
			s.Username = newUsername
			sessions[token] = s
		}
	}
}

// ActiveCount retourne le nombre de sessions valides, pour la supervision.
func ActiveCount() int {
	mu.Lock()
	defer mu.Unlock()
	purgeExpiredLocked()
	return len(sessions)
}

// purgeExpiredLocked retire les sessions expirées. Le verrou doit être tenu.
//
// La map ne rétrécissait jamais : chaque connexion y ajoutait une entrée
// conservée indéfiniment, même longtemps après expiration. Sur un serveur qui
// tourne des mois, c'était une fuite mémoire lente et un stock de jetons périmés
// gardés sans raison.
func purgeExpiredLocked() {
	now := time.Now()
	if now.Sub(lastPurge) < purgeInterval() {
		return
	}
	lastPurge = now

	removed := 0
	for token, s := range sessions {
		if s.ExpiresAt.Before(now) {
			delete(sessions, token)
			removed++
		}
	}
	if removed > 0 {
		logs.Write_Log("DEBUG", "session: "+strconv.Itoa(removed)+" session(s) expirée(s) purgée(s)")
	}
}
