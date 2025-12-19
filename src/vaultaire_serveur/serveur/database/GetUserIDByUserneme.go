package database

import (
	"DUCKY/serveur/logs"
	"database/sql"
	"fmt"
)

func Get_User_ID_By_Username(db *sql.DB, username string) (int, error) {
	injection := SanitizeInput(username)
	if injection != nil {
		return 0, injection
	}
	var userID int
	query := `SELECT id_user FROM users WHERE username = ?`

	err := db.QueryRow(query, username).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows {
			logs.WriteLog("db", "utilisateur non trouvé "+username+" : "+err.Error())
			return 0, fmt.Errorf("utilisateur non trouvé")
		}
		logs.WriteLog("db", "erreur lors de la récupération de l'ID utilisateur: "+err.Error())
		return 0, fmt.Errorf("erreur lors de la récupération de l'ID utilisateur: %v", err)
	}

	return userID, nil
}
