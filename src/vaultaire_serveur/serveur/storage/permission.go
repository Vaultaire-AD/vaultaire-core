package storage

// ParsedPermission contient les résultats du parsing
type ParsedPermission struct {
	All             bool
	Deny            bool
	NoPropagation   []string // les zones marquées "0(...)"
	WithPropagation []string // les zones marquées "1(...)"
}
