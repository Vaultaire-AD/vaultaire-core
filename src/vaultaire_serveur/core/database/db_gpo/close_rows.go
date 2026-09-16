package dbgpo

import (
	"database/sql"
	"vaultaire/core/logs"
)

// closeRows ferme un *sql.Rows en journalisant l'échec éventuel, comme le reste
// de la couche base du projet.
func closeRows(rows *sql.Rows) {
	if err := rows.Close(); err != nil {
		logs.Write_Log("ERROR", "gpo: fermeture du curseur échouée : "+err.Error())
	}
}
