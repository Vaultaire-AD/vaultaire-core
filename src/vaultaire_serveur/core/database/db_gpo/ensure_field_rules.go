package dbgpo

import (
	"database/sql"
	"fmt"
	"vaultaire/core/gpo"
	"vaultaire/core/logs"
)

// ensureFieldRules garantit qu'un champ déclaré a toujours une règle en base.
//
// Exécuté à CHAQUE démarrage, contrairement au reste du peuplement, et c'est
// volontaire : une règle de champ n'est pas une valeur, c'est la définition de la
// façon dont le champ se valide. Un champ sans règle retombe en mode liste avec
// une liste vide, donc refuse tout — un nouveau champ ajouté au catalogue
// casserait son module sur les bases existantes.
//
// Les INSERT du script sont en INSERT IGNORE : une règle déjà présente, y compris
// modifiée par un administrateur, n'est jamais écrasée. Et comme l'interface ne
// permet pas de supprimer une règle (seulement de la modifier), il n'y a pas de
// risque de rétablir un réglage volontairement retiré.
func ensureFieldRules(db *sql.DB) error {
	statements, err := loadSeedStatements()
	if err != nil {
		return err
	}
	for _, stmt := range statements {
		if stmt.Table != "gpo_field_rule" {
			continue
		}
		res, err := db.Exec(stmt.SQL)
		if err != nil {
			logs.Write_LogCode("ERROR", logs.CodeDBGeneric,
				"gpo: vérification des règles de champ échouée : "+err.Error())
			return fmt.Errorf("gpo: vérification des règles de champ échouée : %v", err)
		}
		if affected, _ := res.RowsAffected(); affected > 0 {
			logs.Write_Log("INFO", fmt.Sprintf(
				"gpo: %d règle(s) de champ manquante(s) créée(s) avec leur mode initial", affected))
			gpo.InvalidateRestrictionCache()
		}
	}
	return checkDeclaredFieldsHaveRules(db)
}
