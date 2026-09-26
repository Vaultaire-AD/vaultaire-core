package dbauthpolicy

import (
	"vaultaire/core/logs"
)

// fallbackPolicy applique le repli décrit dans GetPasswordPolicy.
func fallbackPolicy(previous PasswordPolicySettings, hadPrevious bool, reason string) PasswordPolicySettings {
	// Le plancher survit au repli : une valeur conservée qui serait à zéro —
	// politique lue par une version antérieure au point 100, restée en cache —
	// ouvrirait la règle au moment précis où la base ne répond plus.
	if previous.MinLength < MinLengthPlancher {
		previous.MinLength = MinLengthDefaut
	}
	if hadPrevious {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"authpolicy: politique illisible ("+reason+"), dernière valeur connue conservée")
		return previous
	}
	logs.Write_LogCode("ERROR", logs.CodeDBQuery,
		"authpolicy: politique illisible ("+reason+"), expiration désactivée par sécurité de disponibilité")
	return DisabledPolicy
}
