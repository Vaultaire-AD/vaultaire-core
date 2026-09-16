package dbauthpolicy

// Enabled dit si l'expiration est active.
func (p PasswordPolicySettings) Enabled() bool { return p.MaxAgeDays > 0 }
