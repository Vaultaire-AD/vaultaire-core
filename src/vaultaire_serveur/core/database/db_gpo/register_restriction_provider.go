package dbgpo

import (
	"vaultaire/core/gpo"
	"vaultaire/core/logs"
)

// RegisterRestrictionProvider installe le fournisseur base dans core/gpo, et
// branche le journal des échecs de chargement.
// Appelée depuis CreateTables, après création et peuplement des tables.
func RegisterRestrictionProvider() {
	gpo.SetRestrictionFailureLogger(func(message string) {
		logs.Write_LogCode("ERROR", logs.CodeDBGeneric,
			"gpo: restrictions non chargées, aucune GPO ne peut être validée — "+message)
	})
	gpo.SetRestrictionProvider(Provider{})
}
