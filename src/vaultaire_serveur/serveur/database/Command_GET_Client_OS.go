package database

import (
	"vaultaire/serveur/logs"
	"database/sql"
	"fmt"
)

// Get the client OS from the database with clientsoftwareId
func GetClientOS(db *sql.DB, clientsoftwareId string) (string, error) {
	injection := SanitizeInput(clientsoftwareId)
	if injection != nil {
		return "", injection
	}
	var clientOS string
	query := `SELECT os FROM id_logiciels WHERE computeur_id = ?`

	err := db.QueryRow(query, clientsoftwareId).Scan(&clientOS)
	if err != nil {
		logs.WriteLog("db", "Erreur GetClientOS : "+err.Error())
		return "", fmt.Errorf("erreur GetClientOS : %v", err)
	}

	return clientOS, nil
}
