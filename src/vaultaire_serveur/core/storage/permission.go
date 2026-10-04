package storage

// ParsedPermission contient les résultats du parsing
//
// # « nil » et « deny » ne disent pas la même chose (TO-DO 104)
//
// Aucun vaut pour « nil » : ce groupe n'accorde rien pour cette action. C'est
// aussi la valeur d'une action jamais renseignée. Un autre groupe peut
// accorder : on l'IGNORE.
//
// Refus vaut pour « deny » : un refus EXPLICITE. Il l'emporte sur tout ce que
// les autres groupes du compte accordent, « all » compris.
//
// Le champ s'appelait Deny et portait « nil » : un mot qui disait l'inverse de
// ce qu'il faisait, sur un contrôle d'accès. Voir core/permission/refus.go.
type ParsedPermission struct {
	All             bool
	Aucun           bool     // « nil » : rien d'accordé, ignoré
	Refus           bool     // « deny » : refus explicite, prioritaire
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
	Type               string   // "nil", "all", "deny" ou "custom"
	WithPropagation    []string // domaines où la propagation est activée
	WithoutPropagation []string // domaines sans propagation
}
