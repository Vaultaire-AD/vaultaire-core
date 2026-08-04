package dbauthpolicy

import (
	"vaultaire/core/logs"
)

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
