package database

import (
	"DUCKY/serveur/logs"
	"DUCKY/serveur/storage"
	"database/sql"
	"fmt"
)

func Command_GET_AllUsers(db *sql.DB) ([]storage.GetUsers, error) {
	// Requête SQL pour récupérer tous les utilisateurs
	query := `
		SELECT 
			u.id_user, 
			u.username, 
			u.date_naissance, 
			u.created_at
		FROM 
			users u
	`

	// Exécution de la requête SQL
	rows, err := db.Query(query)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de l'exécution de la requête : "+err.Error())
		return nil, fmt.Errorf("erreur lors de l'exécution de la requête : %v", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
		}
	}()

	// Déclaration d'une slice pour stocker les résultats
	var users []storage.GetUsers
	for rows.Next() {
		// Structure pour stocker un utilisateur
		var user storage.GetUsers
		// Scan des résultats de la requête dans la structure
		if err := rows.Scan(&user.ID, &user.Username, &user.DateNaissance, &user.CreatedAt); err != nil {
			logs.WriteLog("db", "Erreur lors du scan des résultats : "+err.Error())
			return nil, fmt.Errorf("erreur lors du scan des résultats : %v", err)
		}
		// Ajout de l'utilisateur à la slice
		users = append(users, user)
	}

	// Vérifier s'il y a une erreur d'itération des résultats
	if err = rows.Err(); err != nil {
		logs.WriteLog("db", "Erreur lors de l'itération des résultats : "+err.Error())
		return nil, fmt.Errorf("erreur lors de l'itération des résultats : %v", err)
	}

	// Retourner les utilisateurs récupérés
	return users, nil
}
