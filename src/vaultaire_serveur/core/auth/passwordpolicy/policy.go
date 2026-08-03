// Package passwordpolicy porte la règle d'expiration des mots de passe.
//
// POINT UNIQUE INTERROGÉ PAR LES TROIS CHEMINS d'authentification — bind LDAP,
// login web, et Ducky, qui porte PAM. Ce n'est pas un détail d'organisation :
// une règle recopiée dans trois handlers finit par diverger sur le quatrième,
// et une divergence ici s'appelle « le mot de passe expiré passe encore par
// LDAP ».
//
// La décision est séparée de sa donnée. Evaluate est une fonction pure — elle
// reçoit une politique, une date et un instant, et retourne un état — donc
// testable sans base ni horloge système. Check fait la composition : lecture de
// la politique, lecture du compte, appel d'Evaluate.
package passwordpolicy

import (
	"database/sql"
	"time"

	"vaultaire/core/database"
	dbauthpolicy "vaultaire/core/database/db_authpolicy"
)

// State est l'état d'un mot de passe au regard de la politique.
type State string

const (
	// StateValid : rien à signaler.
	StateValid State = "valid"

	// StateWarning : encore valide, mais dans la fenêtre de préavis. L'interface
	// web affiche un avertissement ; aucun chemin ne refuse la connexion.
	StateWarning State = "warning"

	// StateExpired : LDAP et Ducky/PAM refusent. Le web accepte la connexion
	// mais n'autorise que la page de changement de mot de passe.
	StateExpired State = "expired"
)

// Status décrit l'état d'un mot de passe et ce qu'il faut en dire à
// l'utilisateur.
type Status struct {
	State State

	// DaysUntilExpiry est le nombre de jours restants, négatif si dépassé.
	// Sans signification quand PolicyEnabled est faux.
	DaysUntilExpiry int

	// ExpiresAt est la date d'expiration calculée. Nulle si la politique est
	// désactivée.
	ExpiresAt time.Time

	// PolicyEnabled dit si une expiration est configurée. Distinct de
	// « StateValid » : un mot de passe peut être valide sous une politique
	// active, ce qui n'a pas le même sens à afficher qu'une absence de
	// politique.
	PolicyEnabled bool

	// Exempt signale un compte que la politique ne concerne pas — voir Check.
	Exempt bool
}

// IsExpired est le prédicat que les chemins d'authentification interrogent.
func (s Status) IsExpired() bool { return s.State == StateExpired }

// ShouldWarn dit s'il faut afficher un préavis.
func (s Status) ShouldWarn() bool { return s.State == StateWarning }

// Evaluate applique la règle. Fonction pure.
//
// Le calcul se fait en jours entiers et non en durée brute : un mot de passe
// valide « 90 jours » doit expirer le même jour de la journée quelle que soit
// l'heure de sa dernière modification. Comparer des durées à la seconde ferait
// expirer deux comptes changés le même jour à quelques heures d'écart à des
// moments différents, ce qui est incompréhensible pour l'utilisateur et
// ingérable pour le support.
func Evaluate(maxAgeDays, warnDays int, changedAt time.Time, hasDate bool, now time.Time) Status {
	if maxAgeDays <= 0 {
		return Status{State: StateValid, PolicyEnabled: false}
	}

	// Date inconnue alors que la politique est active. Ne devrait pas arriver :
	// le schéma initialise password_changed_at pour tous les comptes existants,
	// et la création en pose une. Si le cas se présente malgré tout — restauration
	// partielle, insertion faite à la main — on considère le mot de passe VALIDE
	// et on laisse une trace, plutôt que de verrouiller un compte sur une donnée
	// manquante. Le même raisonnement que pour la lecture de la politique : le
	// coût d'un refus à tort est sans commune mesure avec celui d'une
	// autorisation à tort.
	if !hasDate {
		return Status{State: StateValid, PolicyEnabled: true}
	}

	expiresAt := changedAt.AddDate(0, 0, maxAgeDays)
	daysLeft := daysBetween(now, expiresAt)

	st := Status{
		DaysUntilExpiry: daysLeft,
		ExpiresAt:       expiresAt,
		PolicyEnabled:   true,
	}
	switch {
	case daysLeft <= 0:
		st.State = StateExpired
	case warnDays > 0 && daysLeft <= warnDays:
		st.State = StateWarning
	default:
		st.State = StateValid
	}
	return st
}

// daysBetween retourne le nombre de jours calendaires de `from` à `to`.
//
// Les deux instants sont ramenés à minuit dans leur fuseau avant soustraction,
// pour que le résultat ne dépende pas de l'heure. Sans cela, un mot de passe
// expirant aujourd'hui à 23 h afficherait « 0 jour restant » le matin et
// basculerait en expiré une heure avant la date affichée.
func daysBetween(from, to time.Time) int {
	f := time.Date(from.Year(), from.Month(), from.Day(), 0, 0, 0, 0, from.Location())
	t := time.Date(to.Year(), to.Month(), to.Day(), 0, 0, 0, 0, to.Location())
	return int(t.Sub(f).Hours() / 24)
}

// Check évalue l'état du mot de passe d'un compte.
//
// COMPTE D'AMORÇAGE EXEMPTÉ. `vaultaire` est le compte de dernier recours : il
// est déjà protégé contre la suppression, le renommage et le kill switch
// (core/database/protected.go). L'expiration le priverait de LDAP et de
// Ducky/PAM sur une simple absence d'entretien, précisément dans la situation
// où l'on en a besoin — quand plus rien d'autre ne fonctionne.
//
// La contrepartie est réelle et assumée : ce compte porte tous les droits et son
// mot de passe n'expire jamais. Il doit donc être traité comme un secret
// d'infrastructure — changé à l'installation, conservé hors ligne, et non
// utilisé au quotidien. C'est documenté dans MFA.md, section « Compte
// d'amorçage ».
//
// En cas d'erreur de lecture, retourne un état valide ET l'erreur. L'appelant
// journalise mais ne refuse pas : refuser sur une erreur de lecture ferait d'un
// incident de base une panne d'authentification totale, sur les trois chemins à
// la fois.
func Check(db *sql.DB, username string) (Status, error) {
	if database.IsProtectedUser(username) {
		return Status{State: StateValid, Exempt: true}, nil
	}

	policy := dbauthpolicy.GetPasswordPolicy(db)
	if !policy.Enabled() {
		return Status{State: StateValid, PolicyEnabled: false}, nil
	}

	state, err := dbauthpolicy.GetAuthState(db, username)
	if err != nil {
		return Status{State: StateValid, PolicyEnabled: true}, err
	}

	return Evaluate(policy.MaxAgeDays, policy.WarnDays,
		state.PasswordChangedAt, state.HasPasswordDate, time.Now()), nil
}

// CheckFromState évalue l'état à partir d'une lecture déjà faite.
//
// Les chemins d'authentification lisent déjà AuthState pour le second facteur :
// leur faire relire le compte pour l'expiration doublerait les requêtes sur le
// trajet le plus fréquent du serveur, et ouvrirait une fenêtre où les deux
// lectures ne verraient pas le même état.
func CheckFromState(db *sql.DB, state dbauthpolicy.AuthState) Status {
	if database.IsProtectedUser(state.Username) {
		return Status{State: StateValid, Exempt: true}
	}
	policy := dbauthpolicy.GetPasswordPolicy(db)
	return Evaluate(policy.MaxAgeDays, policy.WarnDays,
		state.PasswordChangedAt, state.HasPasswordDate, time.Now())
}
