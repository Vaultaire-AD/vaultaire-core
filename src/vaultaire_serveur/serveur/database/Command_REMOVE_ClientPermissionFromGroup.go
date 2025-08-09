package database

import (
	"DUCKY/serveur/logs"
	"database/sql"
	"fmt"
)

// Supprime une permission client d'un groupe
func Command_Remove_ClientPermissionFromGroup(db *sql.DB, groupName, permissionName string) error {
	injection := SanitizeInput(groupName, permissionName)
	if injection != nil {
		return injection
	}
	// Vérifier si le groupe existe
	var groupID int
	queryGroup := `SELECT id_group FROM groups WHERE group_name = ?`
	err := db.QueryRow(queryGroup, groupName).Scan(&groupID)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("groupe %s introuvable", groupName)
		}
		logs.WriteLog("db", "Erreur lors de la récupération du groupe : "+err.Error())
		return fmt.Errorf("erreur lors de la récupération du groupe : %v", err)
	}

	// Vérifier si la permission existe dans la table client_permission (ancienne "permission")
	var permissionID int
	queryPermission := `SELECT id_permission FROM client_permission WHERE name_permission = ?`
	err = db.QueryRow(queryPermission, permissionName).Scan(&permissionID)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("permission %s introuvable", permissionName)
		}
		logs.WriteLog("db", "Erreur lors de la récupération de la permission : "+err.Error())
		return fmt.Errorf("erreur lors de la récupération de la permission : %v", err)
	}

	// Vérifier si la permission est déjà attribuée au groupe
	var count int
	queryCheck := `SELECT COUNT(*) FROM group_permission_logiciel WHERE d_id_group = ? AND d_id_permission = ?`
	err = db.QueryRow(queryCheck, groupID, permissionID).Scan(&count)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la vérification de la permission du groupe : "+err.Error())
		return fmt.Errorf("erreur lors de la vérification de la permission du groupe : %v", err)
	}

	if count == 0 {
		return fmt.Errorf("le groupe %s ne possède pas la permission %s", groupName, permissionName)
	}

	// Supprimer la permission du groupe
	queryRemove := `DELETE FROM group_permission_logiciel WHERE d_id_group = ? AND d_id_permission = ?`
	_, err = db.Exec(queryRemove, groupID, permissionID)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la suppression de la permission : "+err.Error())
		return fmt.Errorf("erreur lors de la suppression de la permission : %v", err)
	}

	return nil
}
