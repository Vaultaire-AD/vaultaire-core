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

	// MinLength est la longueur minimale d'un mot de passe NEUF — TO-DO 100.
	//
	// Dans la MÊME structure que l'expiration, et non dans une politique à
	// part : les deux se règlent ensemble, se lisent ensemble et s'affichent
	// sur le même écran. Deux structures auraient voulu dire deux lectures,
	// deux caches et deux occasions de n'en mettre qu'une à jour.
	//
	// Elle ne s'applique JAMAIS aux mots de passe déjà en base : un durcissement
	// de la règle n'a aucun moyen de recalculer ce qu'il refuserait — le mot de
	// passe n'existe nulle part. Le parc s'y conforme à la première écriture de
	// chacun, comme pour le passage à argon2id.
	MinLength int
}
