package database

import (
	"database/sql"
	"fmt"
	"log"
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

func DeleteDidLogin(db *sql.DB, Username string, computeurID string) error {
	injection := SanitizeIdentifier(computeurID, Username)
	if injection != nil {
		return injection
	}
	idUser, _ := Get_User_ID_By_Username(db, Username)
	idLogiciel, _ := GetIdLogicielByComputeurID(db, computeurID)

	query := "DELETE FROM did_login WHERE d_id_user = ? AND d_id_logiciel = ?"
	stmt, err := db.Prepare(query)
	if err != nil {
		return fmt.Errorf("erreur de préparation de la requête : %w", err)
	}

	defer func() {
		if err := stmt.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
		}
	}()

	result, err := stmt.Exec(idUser, idLogiciel)
	if err != nil {
		return fmt.Errorf("erreur lors de l'exécution de la requête : %w", err)
	}

	raffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("erreur lors de la récupération des lignes affectées : %w", err)
	}

	if raffected == 0 {
		log.Println("Aucune ligne supprimée, vérifiez les valeurs de id_user et id_logiciel")
	} else {
		log.Printf("%d ligne(s) supprimée(s)\n", raffected)
	}

	return nil
}
