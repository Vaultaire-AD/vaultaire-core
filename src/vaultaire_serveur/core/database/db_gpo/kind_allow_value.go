package dbgpo

// Catégories de lignes dans gpo_restriction.
const (
	KindAllowValue = "allow_value" // valeur autorisée pour un champ de module
	KindPathAllow  = "path_allow"  // préfixe de chemin autorisé
	KindPathDeny   = "path_deny"   // préfixe de chemin refusé
	KindEnvDeny    = "env_deny"    // variable d'environnement interdite
)
