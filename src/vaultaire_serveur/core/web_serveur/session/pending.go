package session

import (
	"sync"
	"time"

	"vaultaire/core/logs"
)

// Sessions intermédiaires du second facteur.
//
// UN REGISTRE SÉPARÉ, ET PAS UN CHAMP « étape » DANS Session. C'est le point
// important de ce fichier.
//
// Avec un drapeau sur la session ordinaire, tout handler qui appelle
// ValidateToken sans penser à consulter ce drapeau accorderait l'accès à
// quelqu'un qui n'a pas encore présenté son second facteur. Il y a une trentaine
// de handlers, et le prochain sera écrit par quelqu'un qui n'aura pas ce fichier
// en tête. Avec deux registres, ValidateToken ne peut PAS voir un jeton en
// attente : la protection ne dépend plus de la vigilance de l'appelant, elle est
// dans la structure.
//
// Le cookie porte d'ailleurs un autre nom (`mfa_pending` et non `session_token`),
// pour que même une confusion de cookie ne puisse pas franchir la frontière.

// pendingDuration borne la durée de l'étape intermédiaire.
//
// Cinq minutes : le temps de sortir son téléphone, de le déverrouiller et de
// recopier six chiffres, avec de la marge. Au-delà, l'utilisateur recommence
// depuis le mot de passe — ce qui n'est pas grave — tandis qu'une fenêtre longue
// laisserait traîner un jeton qui vaut « mot de passe déjà validé ».
const pendingDuration = 5 * time.Minute

// maxMFAAttempts borne le nombre de codes essayés sur un même jeton.
//
// Six chiffres, c'est un million de combinaisons, mais la fenêtre de tolérance
// en accepte trois à la fois : environ une chance sur 333 000 par essai. Sans
// borne, un script pourrait tenter des dizaines de milliers de codes pendant les
// cinq minutes de validité du jeton et atteindre une probabilité de succès très
// réelle. Trois essais ramènent le risque à l'insignifiance, et correspondent à
// ce qu'un humain fait avant de comprendre que son horloge est décalée.
const maxMFAAttempts = 3

// PendingSession est une authentification à mi-chemin : le mot de passe est
// vérifié, le second facteur ne l'est pas encore.
type PendingSession struct {
	Username  string
	ExpiresAt time.Time
	Attempts  int
}

var (
	pendingSessions = make(map[string]PendingSession)
	pendingMu       sync.RWMutex
)

// CreatePending ouvre une session intermédiaire et retourne son jeton.
//
// Retourne une chaîne vide si le tirage aléatoire échoue — même règle que
// CreateSession : pas de jeton prévisible, donc pas de connexion.
func CreatePending(username string) string {
	token, err := generateToken()
	if err != nil {
		return ""
	}

	pendingMu.Lock()
	defer pendingMu.Unlock()
	purgePendingLocked()

	pendingSessions[token] = PendingSession{
		Username:  username,
		ExpiresAt: time.Now().Add(pendingDuration),
	}
	return token
}

// PendingUsername retourne le compte associé à un jeton intermédiaire.
//
// Ne consomme rien : la page de saisie du code est affichée avant d'être
// soumise, et un simple rechargement ne doit pas invalider l'étape.
func PendingUsername(token string) (string, bool) {
	pendingMu.RLock()
	s, exists := pendingSessions[token]
	pendingMu.RUnlock()

	if !exists {
		return "", false
	}
	if s.ExpiresAt.Before(time.Now()) {
		DeletePending(token)
		return "", false
	}
	return s.Username, true
}

// RegisterFailedMFA compte un essai raté et dit si le jeton reste utilisable.
//
// Retourne false quand le quota est atteint : le jeton est alors détruit, et
// l'utilisateur repart du mot de passe. Détruire plutôt que verrouiller
// temporairement évite d'inventer un second mécanisme de blocage à côté du kill
// switch — recommencer coûte peu à un utilisateur légitime, et beaucoup à un
// script qui doit refaire une authentification complète tous les trois essais.
func RegisterFailedMFA(token string) bool {
	pendingMu.Lock()
	defer pendingMu.Unlock()

	s, exists := pendingSessions[token]
	if !exists {
		return false
	}
	s.Attempts++
	if s.Attempts >= maxMFAAttempts {
		delete(pendingSessions, token)
		logs.Write_LogCode("SECURITY", logs.CodeWebSession,
			"session: trop d'échecs de second facteur pour "+s.Username+", étape annulée")
		return false
	}
	pendingSessions[token] = s
	return true
}

// DeletePending invalide un jeton intermédiaire.
func DeletePending(token string) {
	pendingMu.Lock()
	defer pendingMu.Unlock()
	delete(pendingSessions, token)
}

// DeletePendingOf ferme les étapes intermédiaires d'un compte.
//
// Appelée par le kill switch en même temps que les sessions ordinaires : sans
// cela, un compte révoqué entre la saisie de son mot de passe et celle de son
// code pourrait terminer sa connexion, et ouvrir une vraie session malgré la
// révocation.
func DeletePendingOf(username string) int {
	pendingMu.Lock()
	defer pendingMu.Unlock()

	closed := 0
	for token, s := range pendingSessions {
		if s.Username == username {
			delete(pendingSessions, token)
			closed++
		}
	}
	return closed
}

// purgePendingLocked retire les étapes expirées. Le verrou doit être tenu.
//
// Sans borne de fréquence, contrairement au registre principal : ce registre
// reste petit — quelques secondes de vie par entrée — et n'est parcouru qu'à
// l'ouverture d'une étape, pas à chaque requête.
func purgePendingLocked() {
	now := time.Now()
	for token, s := range pendingSessions {
		if s.ExpiresAt.Before(now) {
			delete(pendingSessions, token)
		}
	}
}
