package database

import (
	"database/sql"
	"fmt"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
)

// Récupère toutes les permissions
func Command_GET_AllClientPermissions(db *sql.DB) ([]storage.ClientPermission, error) {
	var permissions []storage.ClientPermission

	query := `
	SELECT 
		id_permission,
		name_permission,
		is_admin
	FROM client_permission
	`

	rows, err := db.Query(query)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la récupération des permissions clients : "+err.Error())
		return nil, err
	}
	defer func() {
		if err := rows.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
		}
	}()
	for rows.Next() {
		var permission storage.ClientPermission
		if err := rows.Scan(&permission.ID, &permission.Name, &permission.IsAdmin); err != nil {
			logs.WriteLog("db", "Erreur lors du scan des permissions clients : "+err.Error())
			return nil, err
		}
		permissions = append(permissions, permission)
	}

	// rows.Err() distingue « la lecture est terminée » de « la lecture s'est
	// interrompue ». Sans ce contrôle, une coupure en cours d'itération rend un
	// résultat PARTIEL présenté comme complet.
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return permissions, nil
}

func Command_GET_ClientPermissionByName(db *sql.DB, name string) (*storage.ClientPermission, error) {
	query := `
		SELECT cp.id_permission, cp.name_permission, cp.is_admin
		FROM client_permission cp
		WHERE cp.name_permission = ?
		LIMIT 1
	`

	var permission storage.ClientPermission
	err := db.QueryRow(query, name).Scan(&permission.ID, &permission.Name, &permission.IsAdmin)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la récupération de la permission client par nom : "+err.Error())
		return nil, err
	}

	return &permission, nil
}

// AddPermissionToSoftware ajoute une permission à un logiciel dans un groupe
func Command_ADD_PermissionToSoftwareGroup(db *sql.DB, permissionName string, groupName string) error {
	injection := SanitizeIdentifier(permissionName, groupName)
	if injection != nil {
		return injection
	}

	// Vérifier si la permission existe (client_permission)
	permissionID, found, err := LookupClientPermissionID(db, permissionName)
	if err != nil {
		logs.WriteLog("db", "❌ Erreur lors de la récupération de la permission: "+err.Error())
		return fmt.Errorf("❌ Erreur lors de la récupération de la permission: %v", err)
	}
	if !found {
		logs.Write_LogCode("WARNING", logs.CodeDBGeneric, "database: Permission introuvable "+permissionName)
		return fmt.Errorf("❌ Permission '%s' introuvable", permissionName)
	}

	// Vérifier si le groupe existe
	groupID, found, err := LookupGroupID(db, groupName)
	if err != nil {
		logs.WriteLog("db", "❌ Erreur lors de la récupération du groupe: "+err.Error())
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
		logs.WriteLog("db", "❌ Erreur lors de la vérification de la permission pour le logiciel dans le groupe: "+err.Error())
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
		logs.WriteLog("db", "❌ Erreur lors de l'ajout de la permission au logiciel dans le groupe: "+err.Error())
		return fmt.Errorf("❌ Erreur lors de l'ajout de la permission au logiciel dans le groupe: %v", err)
	}

	fmt.Printf("✅ La permission '%s' a été ajoutée au groupe '%s' avec succès !\n", permissionName, groupName)
	return nil
}

// Supprime une permission client d'un groupe
func Command_Remove_ClientPermissionFromGroup(db *sql.DB, groupName, permissionName string) error {
	injection := SanitizeIdentifier(groupName, permissionName)
	if injection != nil {
		return injection
	}
	// Vérifier si le groupe existe
	groupID, found, err := LookupGroupID(db, groupName)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la récupération du groupe : "+err.Error())
		return fmt.Errorf("erreur lors de la récupération du groupe : %v", err)
	}
	if !found {
		return fmt.Errorf("groupe %s introuvable", groupName)
	}

	// Vérifier si la permission existe dans la table client_permission (ancienne "permission")
	permissionID, found, err := LookupClientPermissionID(db, permissionName)
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

// Command_Remove_UserPermissionFromGroup retire une permission UTILISATEUR d'un
// groupe.
//
// CETTE FONCTION N'A JAMAIS FONCTIONNÉ, sur deux défauts distincts, trouvés en
// redirigeant les résolutions d'identifiant recopiées (TO-DO_Database §2.2) :
//
//  1. Elle résolvait le nom de la permission dans client_permission, la table
//     des permissions CLIENT. Les deux familles sont numérotées séparément :
//     l'identifiant obtenu ne désignait donc pas la permission demandée, quand
//     il existait.
//  2. Elle interrogeait puis supprimait dans group_permission_user, une table
//     qui n'existe pas — le schéma déclare group_user_permission, avec la
//     colonne d_id_user_permission. MySQL rendait « table inconnue » dès le
//     COUNT, et la fonction retournait « erreur lors de la vérification de la
//     permission du groupe ».
//
// Conséquence : retirer une permission utilisateur d'un groupe échouait par les
// deux chemins offerts, `vlt remove -g <groupe> -pu <permission>` et le bouton
// de la page groupe. En web l'appelant ne teste que « == nil », donc le clic ne
// produisait aucun message : l'administrateur voyait la permission rester en
// place sans explication. Un droit accordé ne pouvait plus être repris, ce qui
// en fait un défaut de sécurité et pas seulement une gêne — le contournement
// était de supprimer la permission entière, donc de la retirer à TOUS les
// groupes.
//
// Même famille de faute que DeleteGroup (§1.4), qui visait elle aussi des tables
// inexistantes : du code jamais exécuté sur une vraie base.
func Command_Remove_UserPermissionFromGroup(db *sql.DB, groupName, permissionName string) error {
	injection := SanitizeIdentifier(groupName, permissionName)
	if injection != nil {
		return injection
	}
	// Dernier maillon de la chaîne d'accès administrateur : voir protected.go.
	if err := GuardProtectedUserPermissionUnlink(groupName, permissionName); err != nil {
		return err
	}

	// Vérifier si le groupe existe
	groupID, found, err := LookupGroupID(db, groupName)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la récupération du groupe : "+err.Error())
		return fmt.Errorf("erreur lors de la récupération du groupe : %v", err)
	}
	if !found {
		return fmt.Errorf("groupe %s introuvable", groupName)
	}

	// Vérifier si la permission existe (user_permission, pas client_permission)
	permissionID, found, err := LookupUserPermissionID(db, permissionName)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la récupération de la permission : "+err.Error())
		return fmt.Errorf("erreur lors de la récupération de la permission : %v", err)
	}
	if !found {
		return fmt.Errorf("permission %s introuvable", permissionName)
	}

	// Vérifier si la permission est bien attribuée au groupe
	var count int
	queryCheck := `SELECT COUNT(*) FROM group_user_permission WHERE d_id_group = ? AND d_id_user_permission = ?`
	err = db.QueryRow(queryCheck, groupID, permissionID).Scan(&count)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la vérification de la permission du groupe : "+err.Error())
		return fmt.Errorf("erreur lors de la vérification de la permission du groupe : %v", err)
	}

	if count == 0 {
		return fmt.Errorf("le groupe %s ne possède pas la permission %s", groupName, permissionName)
	}

	// Supprimer la permission du groupe
	queryRemove := `DELETE FROM group_user_permission WHERE d_id_group = ? AND d_id_user_permission = ?`
	_, err = db.Exec(queryRemove, groupID, permissionID)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la suppression de la permission : "+err.Error())
		return fmt.Errorf("erreur lors de la suppression de la permission : %v", err)
	}

	logs.Write_LogCode("DEBUG", logs.CodeNone,
		fmt.Sprintf("database: permission utilisateur %s retirée du groupe %s", permissionName, groupName))
	return nil
}
