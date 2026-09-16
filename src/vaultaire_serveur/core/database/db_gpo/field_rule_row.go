package dbgpo

import (
	"time"
)

// FieldRuleRow est une règle de champ telle qu'affichée dans l'interface.
type FieldRuleRow struct {
	ID           int
	ModuleType   string
	FieldName    string
	Mode         string
	AllowPattern string
	DenyPattern  string
	Note         string
	UpdatedBy    string
	UpdatedAt    time.Time
}
