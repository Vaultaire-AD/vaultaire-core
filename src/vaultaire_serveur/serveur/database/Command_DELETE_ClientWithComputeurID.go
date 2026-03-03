package database

import (
	"vaultaire/serveur/logs"
	"database/sql"
	"fmt"
)

// Supprime un client via son computeur_id
func Command_DELETE_ClientWithComputeurID(db *sql.DB, computeurID string) error {
	injection := SanitizeInput(computeurID)
	if injection != nil {
		return injection
	}
	query := `DELETE FROM id_logiciels WHERE computeur_id = ?`
	_, err := db.Exec(query, computeurID)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la suppression du client : "+err.Error())
		return fmt.Errorf("erreur lors de la suppression du client %s : %v", computeurID, err)
	}
	logs.WriteLog("db", fmt.Sprintf("Client %s supprimé avec succès", computeurID))
	return nil
}
