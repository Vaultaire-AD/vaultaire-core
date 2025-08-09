package database

import (
	"DUCKY/serveur/logs"
	"database/sql"
	"fmt"
)

func Get_Client_Software_PublicKey(db *sql.DB, clientSoftwareID string) (string, error) {
	injection := SanitizeInput(clientSoftwareID)
	if injection != nil {
		return "", injection
	}
	var publicKey string
	query := `SELECT public_key FROM id_logiciels WHERE computeur_id = ?`

	err := db.QueryRow(query, clientSoftwareID).Scan(&publicKey)
	if err != nil {
		if err == sql.ErrNoRows {
			logs.WriteLog("db", "clé publique non trouvée pour clientSoftware ID"+err.Error())
			return "", fmt.Errorf("clé publique non trouvée pour clientSoftware ID %s", clientSoftwareID)
		}
		logs.WriteLog("db", "erreur lors de la récupération de la clé publique du clientSoftware : "+err.Error())
		return "", fmt.Errorf("erreur lors de la récupération de la clé publique du clientSoftware : %v", err)
	}

	return publicKey, nil
}
