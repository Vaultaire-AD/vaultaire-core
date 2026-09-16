package dbgpo

import (
	"database/sql"
	"fmt"
	"vaultaire/core/gpo"
	"vaultaire/core/logs"
)

// pruneOrphanAllowValues supprime les valeurs de liste simple posées sur un champ
// qui porte désormais des définitions à contenu.
//
// Rattrapage nécessaire pour les bases créées par une version antérieure, où les
// jeux de commandes sudo étaient de simples noms. Ces lignes apparaîtraient
// encore dans le menu déroulant du module alors qu'aucune définition ne leur
// correspond : la GPO serait sélectionnable puis refusée à l'enregistrement.
func pruneOrphanAllowValues(db *sql.DB) error {
	for _, field := range gpo.DynamicFields() {
		if !field.HasPayload() {
			continue
		}
		res, err := db.Exec(
			`DELETE FROM gpo_restriction WHERE kind = ? AND module_type = ? AND field_name = ?`,
			KindAllowValue, field.ModuleType, field.FieldName)
		if err != nil {
			return fmt.Errorf("gpo: nettoyage des valeurs orphelines de %s/%s impossible : %v",
				field.ModuleType, field.FieldName, err)
		}
		if affected, _ := res.RowsAffected(); affected > 0 {
			logs.Write_Log("INFO", fmt.Sprintf(
				"gpo: %d valeur(s) de liste simple retirée(s) de %s/%s — ce champ utilise désormais des définitions à contenu",
				affected, field.ModuleType, field.FieldName))
			gpo.InvalidateRestrictionCache()
		}
	}
	return nil
}
