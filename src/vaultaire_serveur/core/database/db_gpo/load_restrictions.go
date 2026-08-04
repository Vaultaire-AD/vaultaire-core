package dbgpo

import (
	"fmt"
	"vaultaire/core/database"
	"vaultaire/core/gpo"
)

// LoadRestrictions implémente gpo.RestrictionProvider.
func (Provider) LoadRestrictions() (gpo.RestrictionSet, error) {
	db := database.GetDatabase()
	if db == nil {
		return gpo.RestrictionSet{}, fmt.Errorf("connexion base indisponible")
	}
	return loadRestrictions(db)
}
