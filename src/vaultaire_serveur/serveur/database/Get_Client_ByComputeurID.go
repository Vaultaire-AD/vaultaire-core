package database

import (
	"DUCKY/serveur/logs"
	"database/sql"
	"fmt"
)

// Get_ClientID_By_ComputerID récupère l'ID du client via l'ID du computer
func Get_ClientID_By_ComputerID(db *sql.DB, computerID string) (int, error) {
	var clientID int
	query := `
		SELECT d_id_group
		FROM logiciel_group lg
		JOIN id_logiciels l ON l.id_logiciel = lg.d_id_logiciel
		WHERE l.computeur_id = ? LIMIT 1;
	`
	err := db.QueryRow(query, computerID).Scan(&clientID)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, fmt.Errorf("aucun client trouvé pour l'ordinateur %s", computerID)
		}
		logs.Write_Log("ERROR", fmt.Sprintf("Erreur Get_ClientID_By_ComputerID: %v", err))
		return 0, err
	}
	return clientID, nil
}
