package dbauthpolicy

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
