package dbauthpolicy

import (
	"database/sql"
	"fmt"
	"strconv"
	"time"
	"vaultaire/core/logs"
)

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
