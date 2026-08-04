package dbclients

import (
	"database/sql"
	"fmt"
	database "vaultaire/core/database"
	"vaultaire/core/logs"
)

func Command_ADD_SoftwareToGroup(db *sql.DB, computeur_id, groupName string) error {
	injection := database.SanitizeIdentifier(computeur_id, groupName)
	if injection != nil {
		return injection
	}
	// Vérifier si le logiciel existe
	logicielID, found, err := database.LookupClientID(db, computeur_id)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la récupération du logiciel : "+err.Error())
		return fmt.Errorf("erreur lors de la récupération du logiciel : %v", err)
	}
	if !found {
		return fmt.Errorf("logiciel avec l'computeur_id %s introuvable", computeur_id)
	}

	// Vérifier si le groupe existe
	groupID, found, err := database.LookupGroupID(db, groupName)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la récupération du groupe : "+err.Error())
		return fmt.Errorf("erreur lors de la récupération du groupe : %v", err)
	}
	if !found {
		return fmt.Errorf("groupe avec le nom %s introuvable", groupName)
	}

	// Vérifier si le logiciel est déjà dans ce groupe
	already, err := clientGroupLinkExists(db, logicielID, groupID)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la vérification du logiciel dans le groupe : "+err.Error())
		return fmt.Errorf("erreur lors de la vérification du logiciel dans le groupe : %v", err)
	}

	if already {
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
