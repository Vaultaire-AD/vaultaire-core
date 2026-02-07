package database

import (
	"database/sql"
	"fmt"
	"vaultaire/serveur/logs"
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
			logs.Write_LogCode("WARNING", logs.CodeDBUserNotFound, "utilisateur non trouvé "+username)
			return 0, fmt.Errorf("utilisateur non trouvé")
		}
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "récupération ID utilisateur: "+err.Error())
		return 0, fmt.Errorf("erreur lors de la récupération de l'ID utilisateur: %v", err)
	}

	return userID, nil
}
