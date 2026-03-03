package database

import (
	"vaultaire/serveur/logs"
	"database/sql"
	"fmt"
)

func Command_REMOVE_GPOFromGroup(db *sql.DB, gpoName, groupName string) error {
	// Sanitize les entrées pour éviter les injections SQL
	injection := SanitizeInput(gpoName, groupName)
	if injection != nil {
		return injection
	}

	// Vérifier si la GPO existe
	var gpoID int
	queryGpo := `SELECT id FROM linux_gpo_distributions WHERE gpo_name = ?`
	err := db.QueryRow(queryGpo, gpoName).Scan(&gpoID)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("GPO avec le nom %s introuvable", gpoName)
		}
		logs.WriteLog("db", "Erreur lors de la récupération de la GPO : "+err.Error())
		return fmt.Errorf("erreur lors de la récupération de la GPO : %v", err)
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

	// Vérifier si la GPO est déjà associée au groupe
	var count int
	queryCheck := `SELECT COUNT(*) FROM group_linux_gpo WHERE d_id_group = ? AND d_id_gpo = ?`
	err = db.QueryRow(queryCheck, groupID, gpoID).Scan(&count)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la vérification de l'association GPO-groupe : "+err.Error())
		return fmt.Errorf("erreur lors de la vérification de l'association GPO-groupe : %v", err)
	}

	// Si la GPO n'est pas associée au groupe, on retourne une erreur
	if count == 0 {
		return fmt.Errorf("la GPO %s n'est pas associée au groupe %s", gpoName, groupName)
	}

	// Retirer la GPO du groupe
	queryRemove := `DELETE FROM group_linux_gpo WHERE d_id_group = ? AND d_id_gpo = ?`
	_, err = db.Exec(queryRemove, groupID, gpoID)
	if err != nil {
		logs.WriteLog("db", "Erreur lors du retrait de la GPO du groupe : "+err.Error())
		return fmt.Errorf("erreur lors du retrait de la GPO du groupe : %v", err)
	}

	return nil
}
