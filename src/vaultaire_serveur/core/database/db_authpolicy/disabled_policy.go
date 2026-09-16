package dbauthpolicy

// DisabledPolicy est la politique par défaut : aucune expiration.
//
// C'est aussi la valeur de repli en cas d'échec de lecture — voir
// GetPasswordPolicy.
var DisabledPolicy = PasswordPolicySettings{MaxAgeDays: 0, WarnDays: defaultWarnDays}
