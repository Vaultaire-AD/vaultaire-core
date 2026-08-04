package dbgpo

import (
	"vaultaire/core/gpo"
)

// PolicySummary est la vue de liste d'une GPO : métadonnées, nombre de modules
// et groupes liés, sans charger le détail des paramètres.
type PolicySummary struct {
	gpo.Policy
	ModuleCount int
}
