package dbpermission

import (
	"database/sql"
	"fmt"
	database "vaultaire/core/database"
	"vaultaire/core/logs"
)

// Supprime une permission client d'un groupe
func Command_Remove_ClientPermissionFromGroup(db *sql.DB, groupName, permissionName string) error {
	injection := database.SanitizeIdentifier(groupName, permissionName)
	if injection != nil {
		return injection
	}
	// Vérifier si le groupe existe
	groupID, found, err := database.LookupGroupID(db, groupName)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la récupération du groupe : "+err.Error())
		return fmt.Errorf("erreur lors de la récupération du groupe : %v", err)
	}
	if !found {
		return fmt.Errorf("groupe %s introuvable", groupName)
	}

	// Vérifier si la permission existe dans la table client_permission (ancienne "permission")
	permissionID, found, err := database.LookupClientPermissionID(db, permissionName)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la récupération de la permission : "+err.Error())
		return fmt.Errorf("erreur lors de la récupération de la permission : %v", err)
	}
	if !found {
		return fmt.Errorf("permission %s introuvable", permissionName)
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
