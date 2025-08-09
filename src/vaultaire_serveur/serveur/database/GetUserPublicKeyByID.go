package database

import (
	"DUCKY/serveur/logs"
	"database/sql"
	"fmt"
)

func Get_Public_Key_By_UserID(db *sql.DB, userID int) (string, error) {
	var publicKey string
	query := `SELECT public_key FROM user_key WHERE d_id_user = ?`

	err := db.QueryRow(query, userID).Scan(&publicKey)
	if err != nil {
		if err == sql.ErrNoRows {
			logs.WriteLog("db", "clé publique non trouvée pour l'utilisateur ID"+err.Error())
			return "", fmt.Errorf("clé publique non trouvée pour l'utilisateur ID %d", userID)
		}
		logs.WriteLog("db", "erreur lors de la récupération de la clé publique: "+err.Error())
		return "", fmt.Errorf("erreur lors de la récupération de la clé publique: %v", err)
	}

	return publicKey, nil
}
