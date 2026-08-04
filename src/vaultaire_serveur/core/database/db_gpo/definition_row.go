package dbgpo

import (
	"time"
)

// DefinitionRow est une définition à contenu telle qu'affichée dans l'interface.
type DefinitionRow struct {
	ID          int
	ModuleType  string
	FieldName   string
	Name        string
	PayloadKind string
	Payload     string
	Note        string
	UpdatedBy   string
	UpdatedAt   time.Time
}
