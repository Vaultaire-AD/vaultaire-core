package dbpermission

import (
	"database/sql"
	"fmt"
	database "vaultaire/core/database"
	"vaultaire/core/logs"
)

// AddPermissionToSoftware ajoute une permission à un logiciel dans un groupe
func Command_ADD_PermissionToSoftwareGroup(db *sql.DB, permissionName string, groupName string) error {
	injection := database.SanitizeIdentifier(permissionName, groupName)
	if injection != nil {
		return injection
	}

	// Vérifier si la permission existe (client_permission)
	permissionID, found, err := database.LookupClientPermissionID(db, permissionName)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"❌ Erreur lors de la récupération de la permission: "+err.Error())
		return fmt.Errorf("❌ Erreur lors de la récupération de la permission: %v", err)
	}
	if !found {
		logs.Write_LogCode("WARNING", logs.CodeDBGeneric, "database: Permission introuvable "+permissionName)
		return fmt.Errorf("❌ Permission '%s' introuvable", permissionName)
	}

	// Vérifier si le groupe existe
	groupID, found, err := database.LookupGroupID(db, groupName)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"❌ Erreur lors de la récupération du groupe: "+err.Error())
		return fmt.Errorf("❌ Erreur lors de la récupération du groupe: %v", err)
	}
	if !found {
		logs.Write_LogCode("WARNING", logs.CodeDBGeneric, "database: Groupe introuvable "+groupName)
		return fmt.Errorf("❌ Groupe '%s' introuvable", groupName)
	}

	// Vérifier si la permission est déjà attribuée
	var exists bool
	err = db.QueryRow(
		"SELECT EXISTS(SELECT 1 FROM group_permission_logiciel WHERE d_id_group = ? AND d_id_permission = ?)",
		groupID, permissionID,
	).Scan(&exists)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"❌ Erreur lors de la vérification de la permission pour le logiciel dans le groupe: "+err.Error())
		return fmt.Errorf("❌ Erreur lors de la vérification de la permission pour le logiciel dans le groupe: %v", err)
	}
	if exists {
		logs.Write_LogCode("WARNING", logs.CodeDBGeneric, "database: La permission "+permissionName+" est déjà attribuée au groupe "+groupName+" pour le logiciel")
		return fmt.Errorf("⚠️ La permission '%s' est déjà attribuée au groupe '%s' pour le logiciel", permissionName, groupName)
	}

	// Ajout de la permission
	_, err = db.Exec(
		"INSERT INTO group_permission_logiciel (d_id_group, d_id_permission) VALUES (?, ?)",
		groupID, permissionID,
	)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"❌ Erreur lors de l'ajout de la permission au logiciel dans le groupe: "+err.Error())
		return fmt.Errorf("❌ Erreur lors de l'ajout de la permission au logiciel dans le groupe: %v", err)
	}

	fmt.Printf("✅ La permission '%s' a été ajoutée au groupe '%s' avec succès !\n", permissionName, groupName)
	return nil
}
