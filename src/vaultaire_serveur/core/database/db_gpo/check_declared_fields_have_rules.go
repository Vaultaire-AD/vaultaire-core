package dbgpo

import (
	"database/sql"
	"fmt"
	"vaultaire/core/gpo"
	"vaultaire/core/logs"
)

// checkDeclaredFieldsHaveRules signale un champ déclaré au catalogue mais absent
// du script de peuplement — une incohérence de développement qui se traduirait
// par un module inutilisable, et qu'il vaut mieux voir dans les journaux au
// démarrage que découvrir en production.
func checkDeclaredFieldsHaveRules(db *sql.DB) error {
	for _, field := range gpo.DynamicFields() {
		var count int
		err := db.QueryRow(
			`SELECT COUNT(*) FROM gpo_field_rule WHERE module_type = ? AND field_name = ?`,
			field.ModuleType, field.FieldName,
		).Scan(&count)
		if err != nil {
			return fmt.Errorf("gpo: vérification de la règle %s/%s impossible : %v",
				field.ModuleType, field.FieldName, err)
		}
		if count == 0 {
			logs.Write_Log("WARNING", fmt.Sprintf(
				"gpo: le champ %s/%s est déclaré au catalogue mais n'a pas de règle dans le script de peuplement — "+
					"il refusera toute valeur jusqu'à ce qu'une règle soit définie dans Admin → GPO → Restrictions",
				field.ModuleType, field.FieldName))
		}
	}
	return nil
}
