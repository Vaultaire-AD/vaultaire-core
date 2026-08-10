package dbgroups

import (
	"database/sql"
	"fmt"
	database "vaultaire/core/database"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
)

func Command_GET_UsersByGroup(db *sql.DB, groupName string) ([]storage.DisplayUsersByGroup, error) {
	injection := database.SanitizeIdentifier(groupName)
	if injection != nil {
		return nil, injection
	}
	query := `
		SELECT 
			u.username, 
			COALESCE(DATE_FORMAT(u.date_naissance, '%Y-%m-%d'), '') AS date_naissance, 
			CASE WHEN dl.d_id_user IS NOT NULL THEN TRUE ELSE FALSE END AS is_connected
		FROM users u
		INNER JOIN users_group ug ON u.id_user = ug.d_id_user
		INNER JOIN groups g ON ug.d_id_group = g.id_group
		LEFT JOIN did_login dl ON u.id_user = dl.d_id_user
		WHERE g.group_name = ?
	`

	rows, err := db.Query(query, groupName)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"Erreur lors de l'exécution de la requête : "+err.Error())
		return nil, fmt.Errorf("erreur lors de l'exécution de la requête : %v", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
		}
	}()

	var users []storage.DisplayUsersByGroup

	for rows.Next() {
		var user storage.DisplayUsersByGroup
		if err := rows.Scan(&user.Username, &user.DateOfBirth, &user.Connected); err != nil {
			logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"Erreur lors du scan des résultats : "+err.Error())
			return nil, fmt.Errorf("erreur lors du scan des résultats : %v", err)
		}
		users = append(users, user)
	}

	if err = rows.Err(); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"Erreur lors de l'itération des résultats : "+err.Error())
		return nil, fmt.Errorf("erreur lors de l'itération des résultats : %v", err)
	}

	if len(users) == 0 {
		logs.Write_LogCode("DEBUG", logs.CodeNone, "database: Aucun utilisateur trouvé pour le groupe : "+groupName)
		return nil, fmt.Errorf("aucun utilisateur trouvé pour le groupe '%s'", groupName)
	}

	return users, nil
}
