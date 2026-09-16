package dbusers

import (
	"database/sql"
	"fmt"
	"vaultaire/core/logs"
)

func Get_User_PasswordHash_By_UserID(db *sql.DB, userID int) (string, error) {
	var passwordHash string
	query := `SELECT password FROM users WHERE id_user = ?`

	err := db.QueryRow(query, userID).Scan(&passwordHash)
	if err != nil {
		if err == sql.ErrNoRows {
			logs.Write_LogCode("WARNING", logs.CodeDBUserNotFound, fmt.Sprintf("utilisateur non trouvé pour l'ID: %d", userID))
			return "", fmt.Errorf("utilisateur non trouvé")
		}
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, fmt.Sprintf("récupération password hash utilisateur ID %d: %s", userID, err.Error()))
		return "", fmt.Errorf("erreur lors de la récupération du password hash: %v", err)
	}

	return passwordHash, nil
}
