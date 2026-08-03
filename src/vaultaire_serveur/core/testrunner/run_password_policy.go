package testrunner

import (
	"fmt"
	"time"

	"vaultaire/core/auth/passwordpolicy"
)

// Tests de la règle d'expiration des mots de passe.
//
// Evaluate est pure — politique, date, instant en entrée, état en sortie — donc
// vérifiable sans base ni attente. C'est la raison pour laquelle la décision a
// été séparée de sa lecture : la règle qui décide de couper l'accès à tout un
// annuaire ne doit pas être une chose qu'on ne peut observer qu'en production.
func testPasswordPolicy() []Result {
	var out []Result

	// Instant de référence fixe. Utiliser time.Now() rendrait la suite
	// dépendante de l'heure d'exécution, donc capable d'échouer une fois par
	// jour au changement de date.
	now := time.Date(2026, 8, 3, 14, 30, 0, 0, time.UTC)
	day := func(d int) time.Time { return now.AddDate(0, 0, d) }

	type tc struct {
		name       string
		maxAge     int
		warn       int
		changedAt  time.Time
		hasDate    bool
		wantState  passwordpolicy.State
		wantDaysLeft int
	}

	cases := []tc{
		// Politique désactivée : aucun mot de passe n'expire, même très ancien.
		{"politique désactivée", 0, 7, day(-3650), true, passwordpolicy.StateValid, 0},

		// Cas nominal : changé aujourd'hui, valide 90 jours.
		{"changé aujourd'hui", 90, 7, now, true, passwordpolicy.StateValid, 90},

		// Juste avant la fenêtre de préavis.
		{"J-8 sur un préavis de 7", 90, 7, day(-82), true, passwordpolicy.StateValid, 8},

		// Premier jour du préavis : la borne est inclusive.
		{"J-7 sur un préavis de 7", 90, 7, day(-83), true, passwordpolicy.StateWarning, 7},

		{"J-1", 90, 7, day(-89), true, passwordpolicy.StateWarning, 1},

		// Le jour même : zéro jour restant vaut expiré, pas « encore valide
		// aujourd'hui ». Une politique à 90 jours doit refuser au 90e, sinon
		// elle en dure 91.
		{"jour de l'expiration", 90, 7, day(-90), true, passwordpolicy.StateExpired, 0},

		{"expiré depuis longtemps", 90, 7, day(-400), true, passwordpolicy.StateExpired, -310},

		// Préavis à zéro : on passe de valide à expiré sans avertissement.
		{"préavis désactivé", 30, 0, day(-29), true, passwordpolicy.StateValid, 1},

		// Date inconnue sous politique active : valide, jamais expiré. Un compte
		// sans date ne doit pas être verrouillé par une donnée manquante.
		{"date de changement inconnue", 90, 7, time.Time{}, false, passwordpolicy.StateValid, 0},
	}

	for _, c := range cases {
		got := passwordpolicy.Evaluate(c.maxAge, c.warn, c.changedAt, c.hasDate, now)
		ok := got.State == c.wantState
		// Le nombre de jours n'a de sens que sous une politique active avec une
		// date connue.
		if ok && c.maxAge > 0 && c.hasDate {
			ok = got.DaysUntilExpiry == c.wantDaysLeft
		}
		out = append(out, Result{
			"Politique mdp: " + c.name, ok,
			fmt.Sprintf("attendu %s/%dj, obtenu %s/%dj",
				c.wantState, c.wantDaysLeft, got.State, got.DaysUntilExpiry)})
	}

	// L'heure de la journée ne doit pas changer le résultat : deux comptes
	// changés le même jour à des heures différentes expirent ensemble.
	morning := time.Date(2026, 5, 5, 6, 0, 0, 0, time.UTC)
	evening := time.Date(2026, 5, 5, 23, 0, 0, 0, time.UTC)
	a := passwordpolicy.Evaluate(90, 7, morning, true, now)
	b := passwordpolicy.Evaluate(90, 7, evening, true, now)
	out = append(out, Result{"Politique mdp: le résultat ne dépend pas de l'heure",
		a.State == b.State && a.DaysUntilExpiry == b.DaysUntilExpiry,
		fmt.Sprintf("matin %s/%dj, soir %s/%dj", a.State, a.DaysUntilExpiry, b.State, b.DaysUntilExpiry)})

	// Un préavis plus long que la validité ne doit pas produire d'état absurde.
	// La lecture des réglages le ramène déjà à la validité, mais Evaluate est
	// appelable directement et ne doit pas s'y perdre.
	odd := passwordpolicy.Evaluate(5, 30, day(-1), true, now)
	out = append(out, Result{"Politique mdp: préavis plus long que la validité",
		odd.State == passwordpolicy.StateWarning,
		fmt.Sprintf("obtenu %s", odd.State)})

	// Les prédicats doivent être cohérents avec l'état : ce sont eux que les
	// chemins d'authentification appellent, pas la comparaison d'état.
	expired := passwordpolicy.Evaluate(30, 7, day(-60), true, now)
	warning := passwordpolicy.Evaluate(30, 7, day(-25), true, now)
	valid := passwordpolicy.Evaluate(30, 7, day(-1), true, now)
	out = append(out, Result{"Politique mdp: IsExpired et ShouldWarn sont cohérents",
		expired.IsExpired() && !expired.ShouldWarn() &&
			warning.ShouldWarn() && !warning.IsExpired() &&
			!valid.IsExpired() && !valid.ShouldWarn(),
		fmt.Sprintf("expiré=%s préavis=%s valide=%s", expired.State, warning.State, valid.State)})

	return out
}
