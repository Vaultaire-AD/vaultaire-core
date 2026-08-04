package dbauthpolicy

import (
	"database/sql"
	"fmt"
	"vaultaire/core/logs"
)

// ensureColumn ajoute une colonne si elle n'existe pas déjà.
//
// `ALTER TABLE ... ADD COLUMN` n'est pas idempotent sous MySQL : il échoue avec
// l'erreur 1060 si la colonne existe. On pourrait avaler ce code d'erreur
// précis, mais cela reviendrait à traiter le cas normal — un serveur qui
// redémarre — comme une erreur, et à masquer du même geste une vraie 1060 venue
// d'ailleurs. La consultation d'information_schema dit ce qu'on veut savoir.
func ensureColumn(db *sql.DB, table, column, definition string) error {
	if !identifierPattern.MatchString(table) || !identifierPattern.MatchString(column) {
		return fmt.Errorf("identifiant de schéma refusé : %s.%s", table, column)
	}

	var count int
	err := db.QueryRow(`SELECT COUNT(*) FROM information_schema.COLUMNS
		WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?`,
		table, column).Scan(&count)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"authpolicy: inspection de "+table+"."+column+" échouée : "+err.Error())
		return fmt.Errorf("inspection de %s.%s : %w", table, column, err)
	}
	if count > 0 {
		return nil
	}

	if _, err := db.Exec("ALTER TABLE `" + table + "` ADD COLUMN `" + column + "` " + definition); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"authpolicy: ajout de "+table+"."+column+" échoué : "+err.Error())
		return fmt.Errorf("ajout de %s.%s : %w", table, column, err)
	}

	logs.Write_Log("INFO", "authpolicy: colonne "+table+"."+column+" ajoutée")
	return nil
}
