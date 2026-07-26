package database

import (
	"database/sql"
	"fmt"
	"vaultaire/core/logs"
)

// Get_User_Salt_By_ID récupère le salt d'un utilisateur en fonction de son ID
func Get_User_Salt_By_UserID(db *sql.DB, userID int) (string, error) {
	var salt string
	query := `SELECT salt FROM users WHERE id_user = ?`

	err := db.QueryRow(query, userID).Scan(&salt)
	if err != nil {
		if err == sql.ErrNoRows {
			logs.Write_LogCode("WARNING", logs.CodeDBUserNotFound, fmt.Sprintf("utilisateur non trouvé pour l'ID: %d", userID))
			return "", fmt.Errorf("utilisateur non trouvé")
		}
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, fmt.Sprintf("récupération salt utilisateur ID %d: %s", userID, err.Error()))
		return "", fmt.Errorf("erreur lors de la récupération du salt utilisateur: %v", err)
	}

	return salt, nil
}
