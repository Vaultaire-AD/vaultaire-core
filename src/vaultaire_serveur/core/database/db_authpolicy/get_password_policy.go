package dbauthpolicy

import (
	"database/sql"
	"time"
)

// GetPasswordPolicy lit la politique globale, avec un cache court.
//
// POURQUOI UN REPLI OUVERT, contrairement au reste du projet. La convention
// Vaultaire est le fail-closed : une restriction GPO illisible n'autorise
// aucune valeur, un domaine illisible exige un droit global. Ici, la même règle
// donnerait « politique illisible, donc tous les mots de passe sont expirés » —
// soit la totalité de l'annuaire verrouillée sur une erreur de lecture, tous
// chemins confondus.
//
// L'asymétrie des conséquences tranche. Un repli fermé transforme un incident
// de base en panne d'authentification complète ; un repli ouvert laisse passer
// un mot de passe expiré, ce qui suppose que l'attaquant en connaisse déjà un
// valide. Le premier risque est certain et total, le second est conditionnel et
// borné.
//
// Le cache réduit encore la fenêtre : une lecture réussie sert de valeur de
// repli aux suivantes, donc un incident bref ne change rien au comportement.
// L'échec est journalisé en ERROR à chaque fois — il ne doit pas passer
// inaperçu sous prétexte qu'il est bénin.
func GetPasswordPolicy(db *sql.DB) PasswordPolicySettings {
	settingsMu.RLock()
	if cachedPolicySet && time.Since(cachedPolicyAt) < settingsCacheTTL {
		p := cachedPolicy
		settingsMu.RUnlock()
		return p
	}
	previous, hadPrevious := cachedPolicy, cachedPolicySet
	settingsMu.RUnlock()

	if db == nil {
		return fallbackPolicy(previous, hadPrevious, "base indisponible")
	}

	values, err := readSettings(db, SettingPasswordMaxAgeDays, SettingPasswordWarnDays)
	if err != nil {
		return fallbackPolicy(previous, hadPrevious, err.Error())
	}

	policy := PasswordPolicySettings{
		MaxAgeDays: parseBounded(values[SettingPasswordMaxAgeDays], 0, maxAgeDaysLimit, 0),
		WarnDays:   parseBounded(values[SettingPasswordWarnDays], 0, warnDaysLimit, defaultWarnDays),
	}
	// Un préavis plus long que la validité n'a pas de sens : le compte serait en
	// avertissement permanent dès sa création. On le ramène à la validité plutôt
	// que de refuser la politique entière.
	if policy.Enabled() && policy.WarnDays > policy.MaxAgeDays {
		policy.WarnDays = policy.MaxAgeDays
	}

	settingsMu.Lock()
	cachedPolicy, cachedPolicySet, cachedPolicyAt = policy, true, time.Now()
	settingsMu.Unlock()
	return policy
}
