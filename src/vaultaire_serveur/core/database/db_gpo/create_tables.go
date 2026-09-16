package dbgpo

import (
	"database/sql"
	"fmt"

	"vaultaire/core/database/schematools"
	"vaultaire/core/logs"
)

// CreateTables crée le schéma GPO et supprime les tables de l'ancien modèle.
//
// Appelée depuis main, après dbschema.Create_DataBase : la table gpo_group
// référence groups(id_group), qui doit donc déjà exister.
func CreateTables(db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("gpo: connexion base nulle")
	}

	// Le suivi de conformité est créé avec le reste : une table absente ne se
	// verrait qu'au premier rapport d'un agent, c'est-à-dire en production.
	for _, ddl := range append(append([]string{}, tablesDDL...), complianceTablesDDL...) {
		if _, err := db.Exec(ddl); err != nil {
			logs.Write_LogCode("ERROR", logs.CodeDBGeneric, "gpo: création du schéma échouée : "+err.Error())
			return fmt.Errorf("gpo: création du schéma échouée : %v", err)
		}
	}

	// Colonnes ajoutées après coup.
	//
	// Le CREATE ci-dessus ne fait rien sur une base où la table gpo existe déjà :
	// sans cette migration, le serveur démarrerait normalement et échouerait à la
	// première résolution de politique, en pleine exploitation, sur un chemin qui
	// marchait la veille.
	//
	// Le DEFAULT vaut pour les lignes existantes : toutes les GPO déjà en base
	// passent en 'enforce', c'est-à-dire le comportement qu'elles avaient déjà.
	if err := schematools.EnsureColumn(db, "gpo", "gpo", "drift_mode",
		"VARCHAR(16) NOT NULL DEFAULT 'enforce'"); err != nil {
		return err
	}

	if err := DropLegacyTables(db); err != nil {
		return err
	}

	// Tables de restrictions, peuplement initial des seules tables nouvellement
	// créées, puis enregistrement du fournisseur auprès de core/gpo. L'ordre
	// compte : le fournisseur est installé en dernier, pour qu'aucune validation
	// ne lise des tables encore vides et ne conclue à tort qu'aucune valeur n'est
	// autorisée — la lecture étant désormais fail-closed.
	if err := SetupRestrictions(db); err != nil {
		return err
	}
	RegisterRestrictionProvider()

	logs.Write_Log("INFO", "gpo: schéma déclaratif prêt (gpo, gpo_module, gpo_group, gpo_restriction, gpo_field_rule, gpo_compliance)")
	return nil
}
