package database

import (
	"vaultaire/serveur/logs"
	"database/sql"
	"fmt"
)

// AddPermissionToSoftware ajoute une permission à un logiciel dans un groupe
func Command_ADD_PermissionToSoftwareGroup(db *sql.DB, permissionName string, groupName string) error {
	injection := SanitizeInput(permissionName, groupName)
	if injection != nil {
		return injection
	}

	// Vérifier si la permission existe (client_permission)
	var permissionID int
	err := db.QueryRow(
		"SELECT id_permission FROM client_permission WHERE name_permission = ?",
		permissionName,
	).Scan(&permissionID)
	if err != nil {
		if err == sql.ErrNoRows {
			logs.WriteLog("db", "❌ Permission introuvable "+permissionName)
			return fmt.Errorf("❌ Permission '%s' introuvable", permissionName)
		}
		logs.WriteLog("db", "❌ Erreur lors de la récupération de la permission: "+err.Error())
		return fmt.Errorf("❌ Erreur lors de la récupération de la permission: %v", err)
	}

	// Vérifier si le groupe existe
	var groupID int
	err = db.QueryRow(
		"SELECT id_group FROM groups WHERE group_name = ?",
		groupName,
	).Scan(&groupID)
	if err != nil {
		if err == sql.ErrNoRows {
			logs.WriteLog("db", "❌ Groupe introuvable "+groupName)
			return fmt.Errorf("❌ Groupe '%s' introuvable", groupName)
		}
		logs.WriteLog("db", "❌ Erreur lors de la récupération du groupe: "+err.Error())
		return fmt.Errorf("❌ Erreur lors de la récupération du groupe: %v", err)
	}

	// Vérifier si la permission est déjà attribuée
	var exists bool
	err = db.QueryRow(
		"SELECT EXISTS(SELECT 1 FROM group_permission_logiciel WHERE d_id_group = ? AND d_id_permission = ?)",
		groupID, permissionID,
	).Scan(&exists)
	if err != nil {
		logs.WriteLog("db", "❌ Erreur lors de la vérification de la permission pour le logiciel dans le groupe: "+err.Error())
		return fmt.Errorf("❌ Erreur lors de la vérification de la permission pour le logiciel dans le groupe: %v", err)
	}
	if exists {
		logs.WriteLog("db", "⚠️ La permission "+permissionName+" est déjà attribuée au groupe "+groupName+" pour le logiciel")
		return fmt.Errorf("⚠️ La permission '%s' est déjà attribuée au groupe '%s' pour le logiciel", permissionName, groupName)
	}

	// Ajout de la permission
	_, err = db.Exec(
		"INSERT INTO group_permission_logiciel (d_id_group, d_id_permission) VALUES (?, ?)",
		groupID, permissionID,
	)
	if err != nil {
		logs.WriteLog("db", "❌ Erreur lors de l'ajout de la permission au logiciel dans le groupe: "+err.Error())
		return fmt.Errorf("❌ Erreur lors de l'ajout de la permission au logiciel dans le groupe: %v", err)
	}

	fmt.Printf("✅ La permission '%s' a été ajoutée au groupe '%s' avec succès !\n", permissionName, groupName)
	return nil
}
