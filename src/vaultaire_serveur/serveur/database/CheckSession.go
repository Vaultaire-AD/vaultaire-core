package database

import (
	"DUCKY/serveur/logs"
	"database/sql"
	"fmt"
	"log"
	"time"
)

func CleanUpExpiredSessions(db *sql.DB) error {
	// Obtenir l'heure actuelle
	now := time.Now()

	// Sélectionner les IDs des sessions expirées
	rows, err := db.Query("SELECT d_id_user, key_time_validity FROM did_login")
	if err != nil {
		logs.WriteLog("db", "erreur lors de la lecture des sessions : "+err.Error())
		return fmt.Errorf("erreur lors de la lecture des sessions : %v", err)
	}
	defer rows.Close()

	var expiredUserIDs []int
	for rows.Next() {
		var userID int
		var keyTimeValidity string
		err := rows.Scan(&userID, &keyTimeValidity)
		if err != nil {
			logs.WriteLog("db", "erreur lors de l'extraction des données : "+err.Error())
			return fmt.Errorf("erreur lors de l'extraction des données : %v", err)
		}

		// Convertir key_time_validity en type time.Time
		expirationTime, err := time.Parse("2006-01-02 15:04:05", keyTimeValidity)
		if err != nil {
			logs.WriteLog("db", "erreur lors de la conversion de la date : "+err.Error())
			return fmt.Errorf("erreur lors de la conversion de la date : %v", err)
		}

		// Vérifier si l'entrée est expirée
		if now.After(expirationTime) {
			expiredUserIDs = append(expiredUserIDs, userID)
		}
	}

	// Supprimer les sessions expirées
	for _, userID := range expiredUserIDs {
		_, err := db.Exec("DELETE FROM did_login WHERE d_id_user = ?", userID)
		if err != nil {
			logs.WriteLog("db", "erreur lors de la suppression des sessions expirées : "+err.Error())
			return fmt.Errorf("erreur lors de la suppression des sessions expirées : %v", err)
		}
		log.Printf("Session expirée pour user_id %d supprimée", userID)
	}

	return nil
}

func DeleteDidLogin(db *sql.DB, Username string, computeurID string) error {
	injection := SanitizeInput(computeurID, Username)
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
	defer stmt.Close()

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
