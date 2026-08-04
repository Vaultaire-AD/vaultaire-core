package dbgpo

import (
	"time"
)

// RestrictionRow est une ligne de restriction telle qu'affichée dans l'interface.
type RestrictionRow struct {
	ID         int
	Kind       string
	ModuleType string
	FieldName  string
	Scope      string
	Value      string
	Note       string
	UpdatedBy  string
	UpdatedAt  time.Time
}
