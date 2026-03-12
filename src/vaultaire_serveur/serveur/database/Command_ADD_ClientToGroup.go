package database

import (
	"vaultaire/serveur/logs"
	"database/sql"
	"fmt"
)

func Command_ADD_SoftwareToGroup(db *sql.DB, computeur_id, groupName string) error {
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
			return fmt.Errorf("logiciel avec l'computeur_id %s introuvable", computeur_id)
		}
		logs.WriteLog("db", "Erreur lors de la récupération du logiciel : "+err.Error())
		return fmt.Errorf("erreur lors de la récupération du logiciel : %v", err)
	}

	// Vérifier si le groupe existe
	var groupID int
	queryGroup := `SELECT id_group FROM groups WHERE group_name = ?`
	err = db.QueryRow(queryGroup, groupName).Scan(&groupID)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("groupe avec le nom %s introuvable", groupName)
		}
		logs.WriteLog("db", "Erreur lors de la récupération du groupe : "+err.Error())
		return fmt.Errorf("erreur lors de la récupération du groupe : %v", err)
	}

	// Vérifier si le logiciel est déjà dans ce groupe
	var count int
	queryCheck := `SELECT COUNT(*) FROM logiciel_group WHERE d_id_logiciel = ? AND d_id_group = ?`
	err = db.QueryRow(queryCheck, logicielID, groupID).Scan(&count)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la vérification du logiciel dans le groupe : "+err.Error())
		return fmt.Errorf("erreur lors de la vérification du logiciel dans le groupe : %v", err)
	}

	if count > 0 {
		return fmt.Errorf("le logiciel %s est déjà dans le groupe %s", computeur_id, groupName)
	}

	// Ajouter le logiciel au groupe
	queryAdd := `INSERT INTO logiciel_group (d_id_logiciel, d_id_group) VALUES (?, ?)`
	_, err = db.Exec(queryAdd, logicielID, groupID)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de l'ajout du logiciel au groupe : "+err.Error())
		return fmt.Errorf("erreur lors de l'ajout du logiciel au groupe : %v", err)
	}

	return nil
}
