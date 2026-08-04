package dbauthpolicy

import (
	"database/sql"
	"fmt"
	"strconv"
	"sync"
	"time"

	"vaultaire/core/logs"
)

// Clés de réglage reconnues. Toute autre clé présente en base est ignorée.
const (
	// SettingPasswordMaxAgeDays est la durée de validité d'un mot de passe.
	// 0 désactive l'expiration.
	SettingPasswordMaxAgeDays = "password_max_age_days"

	// SettingPasswordWarnDays est la durée du préavis affiché avant expiration.
	SettingPasswordWarnDays = "password_warn_days"
)

// Bornes de validation.
//
// Le maximum à 3650 jours n'est pas une limite de sécurité mais un garde-fou de
// saisie : une valeur absurde entrée par erreur — un horodatage collé dans le
// champ, par exemple — désactiverait la politique sans le dire, alors qu'un
// refus explicite se voit.
const (
	maxAgeDaysLimit  = 3650
	warnDaysLimit    = 365
	defaultWarnDays  = 7
	settingsCacheTTL = 30 * time.Second
)

// PasswordPolicySettings est la politique telle qu'elle est stockée.
//
// Volontairement sans méthode de décision : ce type traverse la frontière entre
// la base et core/auth/passwordpolicy, qui porte la règle. Y mettre un
// `IsExpired()` ferait remonter la décision dans la couche base, où elle serait
// hors de portée des tests.
type PasswordPolicySettings struct {
	MaxAgeDays int
	WarnDays   int
}

// Enabled dit si l'expiration est active.
func (p PasswordPolicySettings) Enabled() bool { return p.MaxAgeDays > 0 }

// DisabledPolicy est la politique par défaut : aucune expiration.
//
// C'est aussi la valeur de repli en cas d'échec de lecture — voir
// GetPasswordPolicy.
var DisabledPolicy = PasswordPolicySettings{MaxAgeDays: 0, WarnDays: defaultWarnDays}

var (
	settingsMu      sync.RWMutex
	cachedPolicy    = DisabledPolicy
	cachedPolicySet bool
	cachedPolicyAt  time.Time
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

// fallbackPolicy applique le repli décrit dans GetPasswordPolicy.
func fallbackPolicy(previous PasswordPolicySettings, hadPrevious bool, reason string) PasswordPolicySettings {
	if hadPrevious {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"authpolicy: politique illisible ("+reason+"), dernière valeur connue conservée")
		return previous
	}
	logs.Write_LogCode("ERROR", logs.CodeDBQuery,
		"authpolicy: politique illisible ("+reason+"), expiration désactivée par sécurité de disponibilité")
	return DisabledPolicy
}

// parseBounded lit un entier et le ramène dans ses bornes.
//
// Une valeur illisible ou hors bornes retombe sur la valeur par défaut plutôt
// que d'échouer : la table est administrable, et une saisie fautive ne doit pas
// empêcher l'authentification de fonctionner.
func parseBounded(raw string, min, max, def int) int {
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		logs.Write_Log("WARNING", "authpolicy: valeur de réglage illisible "+strconv.Quote(raw)+", valeur par défaut appliquée")
		return def
	}
	if v < min || v > max {
		logs.Write_Log("WARNING", fmt.Sprintf(
			"authpolicy: réglage hors bornes (%d), valeur par défaut appliquée", v))
		return def
	}
	return v
}

// readSettings récupère plusieurs clés en une requête.
func readSettings(db *sql.DB, keys ...string) (map[string]string, error) {
	out := make(map[string]string, len(keys))
	if len(keys) == 0 {
		return out, nil
	}

	query := "SELECT setting_key, setting_value FROM server_settings WHERE setting_key IN (?"
	args := make([]any, 0, len(keys))
	args = append(args, keys[0])
	for _, k := range keys[1:] {
		query += ",?"
		args = append(args, k)
	}
	query += ")"

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	// rows.Err distingue « plus de lignes » d'une rupture en cours de parcours :
	// sans ce contrôle, une lecture interrompue passerait pour une table vide,
	// donc pour une politique désactivée.
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// SetPasswordPolicy écrit la politique globale et invalide le cache.
//
// Les bornes sont revérifiées ici et pas seulement dans le formulaire : une
// requête forgée ne doit pas pouvoir inscrire une valeur que la lecture
// rejettera ensuite silencieusement.
func SetPasswordPolicy(db *sql.DB, policy PasswordPolicySettings, updatedBy string) error {
	if policy.MaxAgeDays < 0 || policy.MaxAgeDays > maxAgeDaysLimit {
		return fmt.Errorf("durée de validité hors bornes (0 à %d jours)", maxAgeDaysLimit)
	}
	if policy.WarnDays < 0 || policy.WarnDays > warnDaysLimit {
		return fmt.Errorf("durée de préavis hors bornes (0 à %d jours)", warnDaysLimit)
	}
	if policy.MaxAgeDays > 0 && policy.WarnDays > policy.MaxAgeDays {
		return fmt.Errorf("le préavis (%d j) ne peut pas dépasser la durée de validité (%d j)",
			policy.WarnDays, policy.MaxAgeDays)
	}

	values := map[string]int{
		SettingPasswordMaxAgeDays: policy.MaxAgeDays,
		SettingPasswordWarnDays:   policy.WarnDays,
	}
	for key, value := range values {
		if _, err := db.Exec(`INSERT INTO server_settings (setting_key, setting_value, updated_by)
			VALUES (?, ?, ?)
			ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value), updated_by = VALUES(updated_by)`,
			key, strconv.Itoa(value), updatedBy); err != nil {
			logs.Write_LogCode("ERROR", logs.CodeDBQuery,
				"authpolicy: écriture du réglage "+key+" échouée : "+err.Error())
			return fmt.Errorf("écriture du réglage %s : %w", key, err)
		}
	}

	// Invalidation immédiate : sans cela, le TTL laisserait l'ancienne politique
	// en vigueur jusqu'à trente secondes après l'enregistrement, et
	// l'administrateur verrait sa modification sans effet.
	settingsMu.Lock()
	cachedPolicy, cachedPolicySet, cachedPolicyAt = policy, true, time.Now()
	settingsMu.Unlock()

	logs.Write_Log("SECURITY", fmt.Sprintf(
		"authpolicy: politique de mot de passe modifiée par %s — validité %d j, préavis %d j",
		updatedBy, policy.MaxAgeDays, policy.WarnDays))
	return nil
}
