package database

import (
	"vaultaire/serveur/logs"
	"vaultaire/serveur/storage"
	"database/sql"
	"fmt"
	"log"
)

// GetConnectedUsers récupère les utilisateurs connectés
func Command_STATUS_GetConnectedUsers(db *sql.DB) ([]storage.UserConnected, error) {
	query := `
		SELECT 
			users.id_user, 
			users.username, 
			users.created_at, 
			did_login.key_time_validity
		FROM 
			did_login
		INNER JOIN 
			users 
		ON 
			did_login.d_id_user = users.id_user
	`

	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("erreur lors de l'exécution de la requête : %v", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
		}
	}()

	var connectedUsers []storage.UserConnected
	for rows.Next() {
		var user storage.UserConnected
		err := rows.Scan(&user.ID, &user.Username, &user.CreatedAt, &user.TokenExpiry)
		if err != nil {
			return nil, fmt.Errorf("erreur lors du scan des résultats : %v", err)
		}
		connectedUsers = append(connectedUsers, user)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("erreur lors de l'itération des résultats : %v", err)
	}

	return connectedUsers, nil
}

func Command_STATUS_GetConnectedUser(db *sql.DB, username string) ([]storage.UserConnected, error) {
	query := `
		SELECT 
			users.id_user, 
			users.username, 
			users.created_at, 
			did_login.key_time_validity
		FROM 
			did_login
		INNER JOIN 
			users 
		ON 
			did_login.d_id_user = users.id_user
		WHERE
			users.username = ?
	`

	rows, err := db.Query(query, username)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("db : Le user '%s' n'existe pas.", username)
			return nil, fmt.Errorf("le user '%s' n'existe pas", username)
		}
		return nil, fmt.Errorf("erreur lors de l'exécution de la requête : %v", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
		}
	}()

	var connectedUsers []storage.UserConnected
	for rows.Next() {
		var user storage.UserConnected
		err := rows.Scan(&user.ID, &user.Username, &user.CreatedAt, &user.TokenExpiry)
		if err != nil {
			return nil, fmt.Errorf("erreur lors du scan des résultats : %v", err)
		}
		connectedUsers = append(connectedUsers, user)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("erreur lors de l'itération des résultats : %v", err)
	}

	return connectedUsers, nil
}
