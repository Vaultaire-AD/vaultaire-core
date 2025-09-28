package storage

// ParsedPermission contient les résultats du parsing
type ParsedPermission struct {
	All             bool
	Deny            bool
	NoPropagation   []string // les zones marquées "0(...)"
	WithPropagation []string // les zones marquées "1(...)"
}

// UserPermissionActions représente les colonnes d'action de la table user_permission
type UserPermissionActions struct {
	None               string
	WebAdmin           string
	Auth               string
	Compare            string
	Search             string
	CanRead            string
	CanWrite           string
	APIReadPermission  string
	APIWritePermission string
}

// PermissionRule représente une règle pour un domaine
type PermissionRule struct {
	Domain    string // domaine, ex: company.fr
	Propagate bool   // true si propagation aux sous-domaines (flag 1)
}

// PermissionAction représente l’action sur une permission
type PermissionAction struct {
	Type               string   // "nil", "all" ou "custom"
	WithPropagation    []string // domaines où la propagation est activée
	WithoutPropagation []string // domaines sans propagation
}
