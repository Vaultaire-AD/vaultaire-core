package dbusers

import (
	"database/sql"
	"fmt"
	database "vaultaire/core/database"
	"vaultaire/core/logs"
)

func Get_User_ID_By_Username(db *sql.DB, username string) (int, error) {
	injection := database.SanitizeIdentifier(username)
	if injection != nil {
		return 0, injection
	}
	userID, found, err := database.LookupUserID(db, username)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "récupération ID utilisateur: "+err.Error())
		return 0, fmt.Errorf("erreur lors de la récupération de l'ID utilisateur: %v", err)
	}
	if !found {
		logs.Write_LogCode("WARNING", logs.CodeDBUserNotFound, "utilisateur non trouvé "+username)
		return 0, fmt.Errorf("utilisateur non trouvé")
	}

	return userID, nil
}
