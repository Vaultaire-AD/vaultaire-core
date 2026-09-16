package dbpermission

import (
	"database/sql"
	"fmt"
	"vaultaire/core/database"
	"vaultaire/core/logs"
)

// AddPermissionToGroup ajoute une permission à un groupe
func Command_ADD_UserPermissionToGroup(db *sql.DB, permissionName string, groupName string) error {
	injection := database.SanitizeIdentifier(permissionName, groupName)
	if injection != nil {
		return injection
	}

	// Vérifier si la permission existe (user_permission)
	permissionID, found, err := database.LookupUserPermissionID(db, permissionName)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"❌ Erreur lors de la récupération de la permission: "+err.Error())
		return fmt.Errorf("❌ Erreur lors de la récupération de la permission: %v", err)
	}
	if !found {
		logs.Write_LogCode("WARNING", logs.CodeDBGeneric, "database: Permission '"+permissionName+"' introuvable")
		return fmt.Errorf("❌ Permission '%s' introuvable", permissionName)
	}

	// Vérifier si le groupe existe
	groupID, found, err := database.LookupGroupID(db, groupName)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"❌ Erreur lors de la récupération du groupe: "+err.Error())
		return fmt.Errorf("❌ Erreur lors de la récupération du groupe: %v", err)
	}
	if !found {
		logs.Write_LogCode("WARNING", logs.CodeDBGeneric, "database: Groupe '"+groupName+"' introuvable")
		return fmt.Errorf("❌ Groupe '%s' introuvable", groupName)
	}

	// Vérifier si la permission est déjà attribuée
	var exists bool
	// Vérifier si la permission est déjà attribuée
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM group_user_permission WHERE d_id_group = ? AND d_id_user_permission = ?)", groupID, permissionID).Scan(&exists)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"❌ Erreur lors de la vérification de la permission du groupe: "+err.Error())
		return fmt.Errorf("❌ Erreur lors de la vérification de la permission du groupe: %v", err)
	}
	if exists {
		logs.Write_LogCode("WARNING", logs.CodeDBGeneric, "database: La permission '"+permissionName+"' est déjà attribuée au groupe '"+groupName+"'")
		return fmt.Errorf("⚠️ La permission '%s' est déjà attribuée au groupe '%s'", permissionName, groupName)
	}

	// Ajouter la permission au groupe
	_, err = db.Exec("INSERT INTO group_user_permission (d_id_group, d_id_user_permission) VALUES (?, ?)", groupID, permissionID)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"❌ Erreur lors de l'ajout de la permission au groupe: "+err.Error())
		return fmt.Errorf("❌ Erreur lors de l'ajout de la permission au groupe: %v", err)
	}

	fmt.Printf("✅ La permission '%s' a été ajoutée au groupe '%s' avec succès !\n", permissionName, groupName)
	return nil
}
