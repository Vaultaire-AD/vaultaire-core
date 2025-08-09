package database

import (
	"DUCKY/serveur/logs"
	"database/sql"
)

func UpdateSessionKeyValidity(db *sql.DB, userID int, logicielID int) error {
	query := `
		UPDATE did_login
		SET key_time_validity = CURRENT_TIMESTAMP
		WHERE d_id_user = ? AND d_id_logiciel = ?
	`

	result, err := db.Exec(query, userID, logicielID)
	if err != nil {
		logs.WriteLog("db", "❌ Erreur lors de la mise à jour de la session : "+err.Error())
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		logs.WriteLog("db", "❌ Impossible de récupérer le nombre de lignes modifiées : "+err.Error())
	}

	if rowsAffected == 0 {
		logs.WriteLog("db", "⚠️ Aucun enregistrement de session à mettre à jour (aucune entrée trouvée).")
		return nil
	}
	logs.WriteLog("db", "✅ key_time_validity mis à jour avec succès.")
	return nil
}
