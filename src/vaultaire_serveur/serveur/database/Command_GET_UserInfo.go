package database

import (
	"vaultaire/serveur/logs"
	"vaultaire/serveur/storage"
	"database/sql"
	"fmt"
)

func Command_GET_UserInfo(db *sql.DB, username string) (*storage.GetUserInfoSingle, error) {
	injection := SanitizeInput(username)
	if injection != nil {
		return nil, injection
	}

	query := `
		SELECT 
			u.username,
			u.firstname,
			u.lastname,
			u.email,
			COALESCE(DATE_FORMAT(u.date_naissance, '%Y-%m-%d'), '') AS date_naissance, 
			COALESCE(g.group_name, '') AS group_name, 
			CASE WHEN dl.d_id_user IS NOT NULL THEN TRUE ELSE FALSE END AS is_connected
		FROM users u
		LEFT JOIN users_group ug ON u.id_user = ug.d_id_user
		LEFT JOIN groups g ON ug.d_id_group = g.id_group
		LEFT JOIN did_login dl ON u.id_user = dl.d_id_user
		WHERE u.username = ?;
	`

	rows, err := db.Query(query, username)
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

	var userInfo storage.GetUserInfoSingle
	userInfo.Username = username
	groupsSet := make(map[string]bool)
	isConnected := false

	for rows.Next() {
		var groupName, dateNaissance string
		var connected bool

		// Récupérer tous les champs
		err := rows.Scan(
			&userInfo.Username,
			&userInfo.Firstname,
			&userInfo.Lastname,
			&userInfo.Email,
			&dateNaissance,
			&groupName,
			&connected,
		)
		if err != nil {
			logs.WriteLog("db", "Erreur lors du scan des résultats : "+err.Error())
			return nil, fmt.Errorf("erreur lors du scan des résultats : %v", err)
		}

		userInfo.DateOfBirth = dateNaissance
		if groupName != "" {
			groupsSet[groupName] = true
		}
		if connected {
			isConnected = true
		}
	}

	for g := range groupsSet {
		userInfo.Groups = append(userInfo.Groups, g)
	}
	userInfo.Connected = isConnected

	if err = rows.Err(); err != nil {
		logs.WriteLog("db", "Erreur lors de l'itération des résultats : "+err.Error())
		return nil, fmt.Errorf("erreur lors de l'itération des résultats : %v", err)
	}

	if userInfo.Username == "" {
		logs.WriteLog("db", "Aucun utilisateur trouvé avec le username : "+username)
		return nil, fmt.Errorf("aucun utilisateur trouvé avec le username '%s'", username)
	}

	return &userInfo, nil
}
