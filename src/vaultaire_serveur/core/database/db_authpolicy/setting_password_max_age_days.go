package dbauthpolicy

// Clés de réglage reconnues. Toute autre clé présente en base est ignorée.
const (
	// SettingPasswordMaxAgeDays est la durée de validité d'un mot de passe.
	// 0 désactive l'expiration.
	SettingPasswordMaxAgeDays = "password_max_age_days"

	// SettingPasswordWarnDays est la durée du préavis affiché avant expiration.
	SettingPasswordWarnDays = "password_warn_days"
)
