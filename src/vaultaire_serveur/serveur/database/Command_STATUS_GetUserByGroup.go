package database

import (
	"DUCKY/serveur/logs"
	"DUCKY/serveur/storage"
	"database/sql"
	"fmt"
)

func Command_STATUS_GetUsersByGroup(db *sql.DB, groupName string) ([]storage.UserConnected, error) {
	injection := SanitizeInput(groupName)
	if injection != nil {
		return nil, injection
	}
	query := `
		SELECT 
			users.id_user, 
			users.username, 
			users.created_at, 
			did_login.key_time_validity
		FROM 
			users_group
		INNER JOIN users ON users_group.d_id_user = users.id_user
		LEFT JOIN did_login ON did_login.d_id_user = users.id_user
		INNER JOIN groups ON users_group.d_id_group = groups.id_group
		WHERE groups.group_name = ?
	`

	rows, err := db.Query(query, groupName)
	if err != nil {
		if err == sql.ErrNoRows {
			logs.WriteLog("db", "Le groupe "+groupName+" n'existe pas.")
			return nil, fmt.Errorf("le groupe '%s' n'existe pas", groupName)
		}
		logs.WriteLog("db", "Erreur lors de l'exécution de la requête : "+err.Error())
		return nil, fmt.Errorf("erreur lors de l'exécution de la requête : %v", err)
	}
	defer rows.Close()

	var users []storage.UserConnected
	for rows.Next() {
		var user storage.UserConnected
		if err := rows.Scan(&user.ID, &user.Username, &user.CreatedAt, &user.TokenExpiry); err != nil {
			logs.WriteLog("db", "Erreur lors du scan des résultats : "+err.Error())
			return nil, fmt.Errorf("erreur lors du scan des résultats : %v", err)
		}
		users = append(users, user)
	}

	if err = rows.Err(); err != nil {
		logs.WriteLog("db", "Erreur lors de l'itération des résultats : "+err.Error())
		return nil, fmt.Errorf("erreur lors de l'itération des résultats : %v", err)
	}

	if len(users) == 0 {
		logs.WriteLog("db", "Aucun utilisateur trouvé pour le groupe "+groupName)
		return nil, fmt.Errorf("aucun utilisateur trouvé pour le groupe '%s'", groupName)
	}

	return users, nil
}
