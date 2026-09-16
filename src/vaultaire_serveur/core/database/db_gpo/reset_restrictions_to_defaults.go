package dbgpo

import (
	"database/sql"
	"fmt"
)

// ResetRestrictionsToDefaults purge les restrictions et rejoue le peuplement.
//
// Sortie de secours : puisque tout est éditable, il faut pouvoir revenir à un
// état connu après une modification malheureuse. C'est le SEUL chemin par lequel
// le socle initial est réécrit sur des tables existantes, et il est explicite,
// réservé au superadmin et journalisé.
func ResetRestrictionsToDefaults(db *sql.DB, actor string) error {
	if err := requireSuperadmin(db, actor, "la réinitialisation"); err != nil {
		return err
	}
	for _, table := range []string{"gpo_restriction", "gpo_field_rule", "gpo_value_definition"} {
		if _, err := db.Exec("DELETE FROM " + table); err != nil {
			return fmt.Errorf("gpo: purge de %s impossible : %v", table, err)
		}
	}
	if err := runSeed(db, nil); err != nil {
		return err
	}
	auditRestriction(actor, "réinitialisation complète", "socle initial réécrit depuis le script de peuplement embarqué")
	return nil
}
