package db_permission

import (
	"vaultaire/serveur/database"
	"vaultaire/serveur/logs"
	"database/sql"
	"fmt"
)

// AddPermissionToGroup ajoute une permission à un groupe
func Command_ADD_UserPermissionToGroup(db *sql.DB, permissionName string, groupName string) error {
	injection := database.SanitizeInput(permissionName, groupName)
	if injection != nil {
		return injection
	}

	// Vérifier si la permission existe (user_permission)
	var permissionID int
	err := db.QueryRow("SELECT id_user_permission FROM user_permission WHERE name = ?", permissionName).Scan(&permissionID)
	if err != nil {
		if err == sql.ErrNoRows {
			logs.WriteLog("db", "❌ Permission '"+permissionName+"' introuvable")
			return fmt.Errorf("❌ Permission '%s' introuvable", permissionName)
		}
		logs.WriteLog("db", "❌ Erreur lors de la récupération de la permission: "+err.Error())
		return fmt.Errorf("❌ Erreur lors de la récupération de la permission: %v", err)
	}

	// Vérifier si le groupe existe
	var groupID int
	err = db.QueryRow("SELECT id_group FROM groups WHERE group_name = ?", groupName).Scan(&groupID)
	if err != nil {
		if err == sql.ErrNoRows {
			logs.WriteLog("db", "❌ Groupe '"+groupName+"' introuvable")
			return fmt.Errorf("❌ Groupe '%s' introuvable", groupName)
		}
		logs.WriteLog("db", "❌ Erreur lors de la récupération du groupe: "+err.Error())
		return fmt.Errorf("❌ Erreur lors de la récupération du groupe: %v", err)
	}

	// Vérifier si la permission est déjà attribuée
	var exists bool
	// Vérifier si la permission est déjà attribuée
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM group_user_permission WHERE d_id_group = ? AND d_id_user_permission = ?)", groupID, permissionID).Scan(&exists)
	if err != nil {
		logs.WriteLog("db", "❌ Erreur lors de la vérification de la permission du groupe: "+err.Error())
		return fmt.Errorf("❌ Erreur lors de la vérification de la permission du groupe: %v", err)
	}
	if exists {
		logs.WriteLog("db", "⚠️ La permission '"+permissionName+"' est déjà attribuée au groupe '"+groupName+"'")
		return fmt.Errorf("⚠️ La permission '%s' est déjà attribuée au groupe '%s'", permissionName, groupName)
	}

	// Ajouter la permission au groupe
	_, err = db.Exec("INSERT INTO group_user_permission (d_id_group, d_id_user_permission) VALUES (?, ?)", groupID, permissionID)
	if err != nil {
		logs.WriteLog("db", "❌ Erreur lors de l'ajout de la permission au groupe: "+err.Error())
		return fmt.Errorf("❌ Erreur lors de l'ajout de la permission au groupe: %v", err)
	}

	fmt.Printf("✅ La permission '%s' a été ajoutée au groupe '%s' avec succès !\n", permissionName, groupName)
	return nil
}
