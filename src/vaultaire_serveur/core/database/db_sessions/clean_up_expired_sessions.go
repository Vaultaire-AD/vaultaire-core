package dbsessions

import (
	"database/sql"
	"fmt"
	"vaultaire/core/logs"
)

// CleanUpExpiredSessions supprime les entrées did_login dont key_time_validity
// est dépassé.
//
// La comparaison se fait entièrement côté SQL (WHERE key_time_validity <
// NOW()) plutôt qu'en récupérant la date en Go pour la reparser : le driver
// MySQL (DSN parseTime=true) renvoie un TIMESTAMP scanné dans un string sous
// forme RFC3339Nano (ex "2026-07-28T15:43:41Z"), alors que le code
// attendait un format "2006-01-02 15:04:05" — ça ne matchait jamais et
// faisait échouer le nettoyage à chaque tick, en boucle, sans jamais rien
// supprimer. Laisser MySQL faire la comparaison de dates élimine ce problème
// de format une fois pour toutes.
func CleanUpExpiredSessions(db *sql.DB) error {
	rows, err := db.Query("SELECT d_id_user FROM did_login WHERE key_time_validity < NOW()")
	if err != nil {
		return fmt.Errorf("erreur lors de la lecture des sessions expirées : %v", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
		}
	}()

	var expiredUserIDs []int
	for rows.Next() {
		var userID int
		if err := rows.Scan(&userID); err != nil {
			return fmt.Errorf("erreur lors de l'extraction des données : %v", err)
		}
		expiredUserIDs = append(expiredUserIDs, userID)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("erreur lors de la lecture des sessions expirées : %v", err)
	}

	// Supprimer les sessions expirées
	for _, userID := range expiredUserIDs {
		_, err := db.Exec("DELETE FROM did_login WHERE d_id_user = ?", userID)
		if err != nil {
			return fmt.Errorf("erreur lors de la suppression des sessions expirées : %v", err)
		}
		logs.Write_Log("INFO", fmt.Sprintf("Session expirée pour user_id %d supprimée", userID))
	}

	return nil
}
