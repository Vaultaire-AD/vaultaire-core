package dbusers

import (
	"database/sql"
	"fmt"
	"vaultaire/core/logs"
)

func Get_User_Password_By_ID(db *sql.DB, id int) (string, string, error) {
	var password string
	var salt string
	query := `SELECT password, salt FROM users WHERE id_user = ?`

	err := db.QueryRow(query, id).Scan(&password, &salt)
	if err != nil {
		if err == sql.ErrNoRows {
			logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"utilisateur non trouvé "+err.Error())
			return "", "", fmt.Errorf("utilisateur non trouvé")
		}
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"erreur lors de la récupération de l'ID utilisateur: "+err.Error())
		return "", "", fmt.Errorf("erreur lors de la récupération de l'ID utilisateur: %v", err)
	}

	return password, salt, nil
}
