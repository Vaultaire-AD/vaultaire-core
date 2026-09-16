package dbgpo

import (
	"database/sql"
	"strings"
	"vaultaire/core/logs"
)

// SetupRestrictions crée les tables de restrictions et n'exécute le peuplement
// initial que pour celles qui viennent d'être créées.
//
// L'existence des tables est constatée AVANT leur création : c'est ce qui
// distingue un premier démarrage d'un redémarrage, et c'est ce qui garantit
// qu'une valeur supprimée depuis l'interface ne réapparaît jamais. Un marqueur
// stocké en base ne l'aurait pas garanti, puisqu'il est lui-même supprimable.
func SetupRestrictions(db *sql.DB) error {
	missing, err := missingRestrictionTables(db)
	if err != nil {
		return err
	}
	if err := createRestrictionTables(db); err != nil {
		return err
	}
	if len(missing) > 0 {
		var names []string
		for _, t := range restrictionTables {
			if missing[t] {
				names = append(names, t)
			}
		}
		logs.Write_Log("INFO", "gpo: tables de restrictions créées ("+strings.Join(names, ", ")+"), peuplement initial")
		if err := runSeed(db, missing); err != nil {
			return err
		}
	}

	// Les règles de champ sont vérifiées à chaque démarrage : elles définissent
	// COMMENT un champ se valide, pas quelles valeurs sont permises. Un champ
	// ajouté au catalogue doit obtenir sa règle même sur une base existante,
	// sinon son module refuserait tout.
	if err := ensureFieldRules(db); err != nil {
		return err
	}

	// Rattrapage des bases antérieures : un champ devenu porteur de définitions
	// ne doit plus avoir de valeurs de liste simple orphelines.
	return pruneOrphanAllowValues(db)
}
