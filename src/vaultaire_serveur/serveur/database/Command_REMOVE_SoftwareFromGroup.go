package database

import (
	"vaultaire/serveur/logs"
	"database/sql"
	"fmt"
)

// Command_Remove_SoftwareFromGroup supprime un logiciel d'un groupe
func Command_Remove_SoftwareFromGroup(db *sql.DB, computeur_id, groupName string) error {
	injection := SanitizeInput(computeur_id, groupName)
	if injection != nil {
		return injection
	}
	// Vérifier si le logiciel existe
	var logicielID int
	queryLogiciel := `SELECT id_logiciel FROM id_logiciels WHERE computeur_id = ?`
	err := db.QueryRow(queryLogiciel, computeur_id).Scan(&logicielID)
	if err != nil {
		if err == sql.ErrNoRows {
			logs.WriteLog("db", fmt.Sprintf("Logiciel avec computeur_id %s introuvable", computeur_id))
			return fmt.Errorf("logiciel avec computeur_id %s introuvable", computeur_id)
		}
		logs.WriteLog("db", fmt.Sprintf("Erreur lors de la récupération du logiciel : %v", err))
		return fmt.Errorf("erreur lors de la récupération du logiciel : %v", err)
	}

	// Vérifier si le groupe existe
	var groupID int
	queryGroup := `SELECT id_group FROM groups WHERE group_name = ?`
	err = db.QueryRow(queryGroup, groupName).Scan(&groupID)
	if err != nil {
		if err == sql.ErrNoRows {
			logs.WriteLog("db", fmt.Sprintf("Groupe %s introuvable", groupName))
			return fmt.Errorf("groupe %s introuvable", groupName)
		}
		logs.WriteLog("db", fmt.Sprintf("Erreur lors de la récupération du groupe : %v", err))
		return fmt.Errorf("erreur lors de la récupération du groupe : %v", err)
	}

	// Vérifier si le logiciel est dans ce groupe
	var count int
	queryCheck := `SELECT COUNT(*) FROM logiciel_group WHERE d_id_logiciel = ? AND d_id_group = ?`
	err = db.QueryRow(queryCheck, logicielID, groupID).Scan(&count)
	if err != nil {
		logs.WriteLog("db", fmt.Sprintf("Erreur lors de la vérification du logiciel dans le groupe : %v", err))
		return fmt.Errorf("erreur lors de la vérification du logiciel dans le groupe : %v", err)
	}

	if count == 0 {
		logs.WriteLog("db", fmt.Sprintf("Le logiciel %s ne fait pas partie du groupe %s", computeur_id, groupName))
		return fmt.Errorf("le logiciel %s ne fait pas partie du groupe %s", computeur_id, groupName)
	}

	// Supprimer le logiciel du groupe
	queryRemove := `DELETE FROM logiciel_group WHERE d_id_logiciel = ? AND d_id_group = ?`
	_, err = db.Exec(queryRemove, logicielID, groupID)
	if err != nil {
		logs.WriteLog("db", fmt.Sprintf("Erreur lors de la suppression du logiciel du groupe : %v", err))
		return fmt.Errorf("erreur lors de la suppression du logiciel du groupe : %v", err)
	}

	// Log de succès
	logs.WriteLog("db", fmt.Sprintf("Logiciel %s retiré du groupe %s", computeur_id, groupName))

	return nil
}
