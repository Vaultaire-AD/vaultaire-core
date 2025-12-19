package database

import (
	"DUCKY/serveur/logs"
	"database/sql"
	"fmt"
)

// Command_GET_UserGroupIDs retourne la liste des ID de groupes pour un username donné
func Command_GET_UserGroupIDs(db *sql.DB, username string) ([]int, error) {
	injection := SanitizeInput(username)
	if injection != nil {
		return nil, injection
	}

	query := `
		SELECT ug.d_id_group
		FROM users_group ug
		INNER JOIN users u ON ug.d_id_user = u.id_user
		WHERE u.username = ?
	`

	rows, err := db.Query(query, username)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de l'exécution de la requête : "+err.Error())
		return nil, fmt.Errorf("erreur lors de l'exécution de la requête : %v", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			logs.Write_Log("ERROR", "Erreur lors de la fermeture des lignes : "+err.Error())
		}
	}()

	var groupIDs []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			logs.WriteLog("db", "Erreur lors du scan des résultats : "+err.Error())
			return nil, fmt.Errorf("erreur lors du scan des résultats : %v", err)
		}
		groupIDs = append(groupIDs, id)
	}

	if err = rows.Err(); err != nil {
		logs.WriteLog("db", "Erreur lors de l'itération des résultats : "+err.Error())
		return nil, fmt.Errorf("erreur lors de l'itération des résultats : %v", err)
	}

	if len(groupIDs) == 0 {
		logs.WriteLog("db", "Aucun groupe trouvé pour l'utilisateur : "+username)
		return nil, fmt.Errorf("aucun groupe trouvé pour l'utilisateur '%s'", username)
	}

	return groupIDs, nil
}
