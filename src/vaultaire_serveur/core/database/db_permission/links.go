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
		logs.WriteLog("db", "❌ Erreur lors de la récupération de la permission: "+err.Error())
		return fmt.Errorf("❌ Erreur lors de la récupération de la permission: %v", err)
	}
	if !found {
		logs.Write_LogCode("WARNING", logs.CodeDBGeneric, "database: Permission '"+permissionName+"' introuvable")
		return fmt.Errorf("❌ Permission '%s' introuvable", permissionName)
	}

	// Vérifier si le groupe existe
	groupID, found, err := database.LookupGroupID(db, groupName)
	if err != nil {
		logs.WriteLog("db", "❌ Erreur lors de la récupération du groupe: "+err.Error())
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
		logs.WriteLog("db", "❌ Erreur lors de la vérification de la permission du groupe: "+err.Error())
		return fmt.Errorf("❌ Erreur lors de la vérification de la permission du groupe: %v", err)
	}
	if exists {
		logs.Write_LogCode("WARNING", logs.CodeDBGeneric, "database: La permission '"+permissionName+"' est déjà attribuée au groupe '"+groupName+"'")
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

// Command_GET_Groups_ByUserPermission retourne la liste des noms de groupes
// qui possèdent la permission utilisateur donnée
func Command_GET_Groups_ByUserPermission(db *sql.DB, permissionName string) ([]string, error) {
	query := `
        SELECT DISTINCT g.group_name
        FROM user_permission up
        INNER JOIN group_user_permission gup ON up.id_user_permission = gup.d_id_user_permission
        INNER JOIN groups g ON g.id_group = gup.d_id_group
        WHERE up.name = ?
    `

	rows, err := db.Query(query, permissionName)
	if err != nil {
		logs.WriteLog("db", "Erreur récupération groupes pour permission user '"+permissionName+"' : "+err.Error())
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var groups []string
	for rows.Next() {
		var g string
		if err := rows.Scan(&g); err != nil {
			logs.WriteLog("db", "Erreur scan groupes pour permission user '"+permissionName+"' : "+err.Error())
			return nil, err
		}
		groups = append(groups, g)
	}

	// rows.Err() distingue « la lecture est terminée » de « la lecture s'est
	// interrompue ». Sans ce contrôle, une coupure en cours d'itération rend un
	// résultat PARTIEL présenté comme complet.
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return groups, nil
}

// ---- Récupérer les domaines d'une permission utilisateur ----
func Command_GET_Domains_ByUserPermission(db *sql.DB, permissionName string) ([]string, error) {
	query := `
		SELECT DISTINCT dg.domain_name
		FROM user_permission up
		INNER JOIN group_user_permission gup ON up.id_user_permission = gup.d_id_user_permission
		INNER JOIN groups g ON g.id_group = gup.d_id_group
		INNER JOIN domain_group dg ON dg.d_id_group = g.id_group
		WHERE up.name = ?
	`

	rows, err := db.Query(query, permissionName)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la récupération des domaines pour la permission utilisateur '"+permissionName+"' : "+err.Error())
		return nil, err
	}
	defer func() {
		if err := rows.Close(); err != nil {
			logs.WriteLog("db", "Erreur lors de la fermeture du rows: "+err.Error())
		}
	}()

	var domains []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			logs.WriteLog("db", "Erreur lors du scan des domaines pour la permission utilisateur '"+permissionName+"' : "+err.Error())
			return nil, err
		}
		domains = append(domains, domain)
	}

	// rows.Err() distingue « la lecture est terminée » de « la lecture s'est
	// interrompue ». Sans ce contrôle, une coupure en cours d'itération rend un
	// résultat PARTIEL présenté comme complet.
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return domains, nil
}

// ---- Récupérer les domaines d'une permission client ----
func Command_GET_Domains_ByClientPermission(db *sql.DB, permissionName string) ([]string, error) {
	query := `
		SELECT DISTINCT dg.domain_name
		FROM client_permission cp
		INNER JOIN group_permission_logiciel gpl ON cp.id_permission = gpl.d_id_permission
		INNER JOIN groups g ON g.id_group = gpl.d_id_group
		INNER JOIN domain_group dg ON dg.d_id_group = g.id_group
		WHERE cp.name_permission = ?
	`

	rows, err := db.Query(query, permissionName)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la récupération des domaines pour la permission client '"+permissionName+"' : "+err.Error())
		return nil, err
	}
	defer func() {
		if err := rows.Close(); err != nil {
			logs.WriteLog("db", "Erreur lors de la fermeture du rows: "+err.Error())
		}
	}()

	var domains []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			logs.WriteLog("db", "Erreur lors du scan des domaines pour la permission client '"+permissionName+"' : "+err.Error())
			return nil, err
		}
		domains = append(domains, domain)
	}

	// rows.Err() distingue « la lecture est terminée » de « la lecture s'est
	// interrompue ». Sans ce contrôle, une coupure en cours d'itération rend un
	// résultat PARTIEL présenté comme complet.
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return domains, nil
}
