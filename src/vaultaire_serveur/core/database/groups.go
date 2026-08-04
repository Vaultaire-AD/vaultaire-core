package database

import (
	"database/sql"
	"fmt"
	"strings"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
)

func CreateGroup(db *sql.DB, groupName string, domainName string) (int64, error) {

	tx, err := db.Begin()
	if err != nil {
		logs.WriteLog("db", "erreur lors de l'initialisation de la transaction CreateGroupe: "+err.Error())
		return 0, fmt.Errorf("erreur lors de l'initialisation de la transaction: %v", err)
	}

	// Insérer le groupe
	result, err := tx.Exec(`INSERT INTO groups (group_name) VALUES (?)`, groupName)
	if err != nil {
		err = tx.Rollback()
		if err != nil {
			logs.WriteLog("db", "erreur lors de l'annulation de la transaction : "+err.Error())
		}
		logs.WriteLog("db", "erreur lors de l'insertion du groupe CreateGroupe: "+err.Error())
		return 0, fmt.Errorf("erreur lors de l'insertion du groupe: %v", err)
	}

	groupID, err := result.LastInsertId()
	if err != nil {
		err = tx.Rollback()
		if err != nil {
			logs.WriteLog("db", "erreur lors de l'annulation de la transaction : "+err.Error())
		}
		logs.WriteLog("db", "erreur lors de la récupération de l'ID du groupe CreateGroupe: "+err.Error())
		return 0, fmt.Errorf("erreur lors de la récupération de l'ID du groupe: %v", err)
	}
	// Insérer le domaine associé
	_, err = tx.Exec(`INSERT INTO domain_group (d_id_group, domain_name) VALUES (?, ?)`, groupID, domainName)
	if err != nil {
		err = tx.Rollback()
		if err != nil {
			logs.WriteLog("db", "erreur lors de l'annulation de la transaction : "+err.Error())
		}
		logs.WriteLog("db", "erreur lors de l'insertion du domaine CreateGroup: "+err.Error())
		return 0, fmt.Errorf("erreur lors de l'insertion du domaine: %v", err)
	}

	err = tx.Commit()
	if err != nil {
		logs.WriteLog("db", "erreur lors de la validation de la transaction CreateGroupe : "+err.Error())
		return 0, fmt.Errorf("erreur lors de la validation de la transaction: %v", err)
	}

	return groupID, nil
}

// DeleteGroup a été supprimée : code mort ET cassé.
//
// Aucun appelant dans tout le dépôt. Mais surtout, elle visait deux tables qui
// n'existent pas : `group_permission` et `groupe`. Le schéma réel porte
// `group_user_permission`, `group_permission_logiciel` et `groups`. Elle aurait
// donc échoué à la première exécution, sur une erreur MySQL de table inconnue.
//
// C'est le danger de ce genre de reste : le nom est parfaitement plausible, la
// signature aussi, et quiconque aurait cherché « comment supprimer un groupe »
// l'aurait appelée en toute confiance. La suppression d'un groupe passe par
// Command_DELETE_GroupWithGroupName, qui connaît le vrai schéma.

// GetGroupIDByName retourne l'identifiant interne d'un groupe depuis son nom.
//
// POINT D'ENTRÉE UNIQUE pour cette question. La même requête était recopiée
// dans dix fonctions du projet ; ce helper existait déjà mais n'était appelé
// par presque personne, et il était le SEUL à ne pas assainir son entrée — les
// copies en ligne, elles, le faisaient. Rediriger les appelants vers lui aurait
// donc affaibli le code au lieu de le renforcer. D'où l'ordre : durcir ici
// d'abord, rediriger ensuite.
//
// Un nom de groupe désigne une entité : liste blanche (SanitizeIdentifier), pas
// liste noire. Le paramètre est déjà passé en requête préparée, donc ce n'est
// pas une protection contre l'injection : c'est un refus des noms que
// l'annuaire n'aurait jamais dû accepter, posé au plus près de la base pour
// couvrir tous les appelants, y compris ceux qui seront écrits plus tard.
func GetGroupIDByName(db *sql.DB, groupName string) (int, error) {
	if err := SanitizeIdentifier(groupName); err != nil {
		return 0, err
	}

	groupID, found, err := LookupGroupID(db, groupName)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"database: lecture de l'ID du groupe '"+groupName+"' échouée : "+err.Error())
		return 0, fmt.Errorf("erreur lors de la récupération de l'ID du groupe '%s' : %v", groupName, err)
	}
	if !found {
		// Le message parlait de « permission », par copier-coller depuis une
		// fonction de permission. Un administrateur qui cherchait pourquoi un
		// groupe manquait trouvait « permission introuvable » dans les
		// journaux, et cherchait au mauvais endroit.
		logs.Write_LogCode("WARNING", logs.CodeDBGeneric,
			fmt.Sprintf("database: groupe '%s' introuvable", groupName))
		return 0, fmt.Errorf("groupe '%s' introuvable", groupName)
	}

	return groupID, nil
}

// Supprime un groupe via son nom
func Command_DELETE_GroupWithGroupName(db *sql.DB, groupName string) error {
	injection := SanitizeIdentifier(groupName)
	if injection != nil {
		return injection
	}
	// Le groupe superadmin n'est pas supprimable : voir protected.go.
	if err := GuardProtectedGroupDeletion(groupName); err != nil {
		return err
	}
	query := `DELETE FROM groups WHERE group_name = ?`
	_, err := db.Exec(query, groupName)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la suppression du groupe : "+err.Error())
		return fmt.Errorf("erreur lors de la suppression du groupe %s : %v", groupName, err)
	}
	logs.Write_LogCode("DEBUG", logs.CodeNone, fmt.Sprintf("database: Groupe %s supprimé avec succès", groupName))
	return nil
}

func Command_ADD_UserToGroup(db *sql.DB, username, groupName string) error {
	injection := SanitizeIdentifier(username, groupName)
	if injection != nil {
		return injection
	}
	// Vérifier si l'utilisateur existe
	userID, found, err := LookupUserID(db, username)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la récupération de l'utilisateur : "+err.Error())
		return fmt.Errorf("erreur lors de la récupération de l'utilisateur : %v", err)
	}
	if !found {
		return fmt.Errorf("utilisateur avec le nom d'utilisateur %s introuvable", username)
	}

	// Vérifier si le groupe existe
	groupID, found, err := LookupGroupID(db, groupName)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la récupération du groupe : "+err.Error())
		return fmt.Errorf("erreur lors de la récupération du groupe : %v", err)
	}
	if !found {
		return fmt.Errorf("groupe avec le nom %s introuvable", groupName)
	}

	// Vérifier si l'utilisateur est déjà dans ce groupe
	already, err := userGroupLinkExists(db, userID, groupID)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la vérification de l'utilisateur dans le groupe : "+err.Error())
		return fmt.Errorf("erreur lors de la vérification de l'utilisateur dans le groupe : %v", err)
	}

	// Si l'utilisateur est déjà dans ce groupe, on ne fait rien
	if already {
		return fmt.Errorf("l'utilisateur %s est déjà membre du groupe %s", username, groupName)
	}

	// Ajouter l'utilisateur au groupe
	queryAdd := `INSERT INTO users_group (d_id_user, d_id_group) VALUES (?, ?)`
	_, err = db.Exec(queryAdd, userID, groupID)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de l'ajout de l'utilisateur au groupe : "+err.Error())
		return fmt.Errorf("erreur lors de l'ajout de l'utilisateur au groupe : %v", err)
	}

	return nil
}

// Command_Remove_UserFromGroup supprime un utilisateur d'un groupe
func Command_Remove_UserFromGroup(db *sql.DB, username, groupName string) error {
	injection := SanitizeIdentifier(username, groupName)
	if injection != nil {
		return injection
	}
	// Retirer vaultaire du groupe vaultaire lui ôterait toutes ses permissions :
	// l'effet est équivalent à une suppression du compte. Voir protected.go.
	if err := GuardProtectedMembership(username, groupName); err != nil {
		return err
	}
	// Vérifier si l'utilisateur existe
	userID, found, err := LookupUserID(db, username)
	if err != nil {
		logs.WriteLog("db", fmt.Sprintf("Erreur lors de la récupération de l'utilisateur : %v", err))
		return fmt.Errorf("erreur lors de la récupération de l'utilisateur : %v", err)
	}
	if !found {
		logs.Write_LogCode("WARNING", logs.CodeDBUserNotFound, fmt.Sprintf("database: Utilisateur %s introuvable", username))
		return fmt.Errorf("utilisateur %s introuvable", username)
	}

	// Vérifier si le groupe existe
	groupID, found, err := LookupGroupID(db, groupName)
	if err != nil {
		logs.WriteLog("db", fmt.Sprintf("Erreur lors de la récupération du groupe : %v", err))
		return fmt.Errorf("erreur lors de la récupération du groupe : %v", err)
	}
	if !found {
		logs.Write_LogCode("WARNING", logs.CodeDBGeneric, fmt.Sprintf("database: Groupe %s introuvable", groupName))
		return fmt.Errorf("groupe %s introuvable", groupName)
	}

	// Vérifier si l'utilisateur est dans ce groupe
	member, err := userGroupLinkExists(db, userID, groupID)
	if err != nil {
		logs.WriteLog("db", fmt.Sprintf("Erreur lors de la vérification de l'utilisateur dans le groupe : %v", err))
		return fmt.Errorf("erreur lors de la vérification de l'utilisateur dans le groupe : %v", err)
	}

	if !member {
		logs.Write_LogCode("WARNING", logs.CodeDBGeneric, fmt.Sprintf("database: L'utilisateur %s ne fait pas partie du groupe %s", username, groupName))
		return fmt.Errorf("l'utilisateur %s ne fait pas partie du groupe %s", username, groupName)
	}

	// Supprimer l'utilisateur du groupe
	queryRemove := `DELETE FROM users_group WHERE d_id_user = ? AND d_id_group = ?`
	_, err = db.Exec(queryRemove, userID, groupID)
	if err != nil {
		logs.WriteLog("db", fmt.Sprintf("Erreur lors de la suppression de l'utilisateur du groupe : %v", err))
		return fmt.Errorf("erreur lors de la suppression de l'utilisateur du groupe : %v", err)
	}

	// Log de succès
	logs.Write_LogCode("DEBUG", logs.CodeNone, fmt.Sprintf("database: Utilisateur %s retiré du groupe %s", username, groupName))

	return nil
}

func Command_GET_GroupDetails(db *sql.DB) ([]storage.GroupDetails, error) {
	query := `
	SELECT 
		g.group_name,
		dg.domain_name,
		COUNT(DISTINCT gp.d_id_permission) AS logiciel_permission_count,
		COUNT(DISTINCT gup.d_id_user_permission) AS user_permission_count,
		COUNT(DISTINCT ug.d_id_user) AS user_count,
		COUNT(DISTINCT lg.d_id_logiciel) AS client_count
	FROM 
		groups g
	LEFT JOIN 
		domain_group dg ON g.id_group = dg.d_id_group
	LEFT JOIN 
		group_permission_logiciel gp ON g.id_group = gp.d_id_group
	LEFT JOIN 
		group_user_permission gup ON g.id_group = gup.d_id_group
	LEFT JOIN 
		users_group ug ON g.id_group = ug.d_id_group
	LEFT JOIN 
		logiciel_group lg ON g.id_group = lg.d_id_group
	GROUP BY 
		g.id_group, dg.domain_name
`

	rows, err := db.Query(query)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de l'exécution de la requête : "+err.Error())
		return nil, fmt.Errorf("erreur lors de l'exécution de la requête : %v", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
		}
	}()

	var groupDetails []storage.GroupDetails

	for rows.Next() {
		var groupName, domainName string
		var logicielPermissionCount, userPermissionCount, userCount, clientCount int

		if err := rows.Scan(&groupName, &domainName, &logicielPermissionCount, &userPermissionCount, &userCount, &clientCount); err != nil {
			logs.WriteLog("db", "Erreur lors du scan des résultats : "+err.Error())
			return nil, fmt.Errorf("erreur lors du scan des résultats : %v", err)
		}

		groupDetails = append(groupDetails, storage.GroupDetails{
			GroupName:               groupName,
			DomainName:              domainName,
			LogicielPermissionCount: logicielPermissionCount,
			UserPermissionCount:     userPermissionCount,
			UserCount:               userCount,
			ClientCount:             clientCount,
		})
	}

	if err = rows.Err(); err != nil {
		logs.WriteLog("db", "Erreur lors de l'itération des résultats : "+err.Error())
		return nil, fmt.Errorf("erreur lors de l'itération des résultats : %v", err)
	}

	return groupDetails, nil
}

// Structure pour stocker les informations du groupe

// Récupérer toutes les infos d'un groupe via son nom
func Command_GET_GroupInfo(db *sql.DB, groupName string) (*storage.GroupInfo, error) {
	injection := SanitizeIdentifier(groupName)
	if injection != nil {
		return nil, injection
	}

	query := `
	SELECT 
		g.id_group,
		g.group_name,
		COALESCE(dg.domain_name, '') AS domain_name,
		COALESCE(GROUP_CONCAT(DISTINCT u.username ORDER BY u.username SEPARATOR ', '), '') AS users,
		-- Permissions utilisateurs (LDAP)
		COALESCE(GROUP_CONCAT(DISTINCT p.name ORDER BY p.name SEPARATOR ', '), '') AS user_permissions,
		COALESCE(GROUP_CONCAT(DISTINCT l.computeur_id ORDER BY l.computeur_id SEPARATOR ', '), '') AS clients,
		-- Permissions clients/logiciels (table client_permission)
		COALESCE(GROUP_CONCAT(DISTINCT cp.name_permission ORDER BY cp.name_permission SEPARATOR ', '), '') AS client_permissions,
		COALESCE(GROUP_CONCAT(DISTINCT gpol.gpo_name ORDER BY gpol.gpo_name SEPARATOR ', '), '') AS gpos
	FROM groups g
	LEFT JOIN domain_group dg ON g.id_group = dg.d_id_group
	LEFT JOIN users_group ug ON g.id_group = ug.d_id_group
	LEFT JOIN users u ON ug.d_id_user = u.id_user
	LEFT JOIN group_user_permission gp ON g.id_group = gp.d_id_group
	LEFT JOIN user_permission p ON gp.d_id_user_permission = p.id_user_permission
	LEFT JOIN logiciel_group lg ON g.id_group = lg.d_id_group
	LEFT JOIN id_logiciels l ON lg.d_id_logiciel = l.id_logiciel
	LEFT JOIN group_permission_logiciel gpl ON g.id_group = gpl.d_id_group
	LEFT JOIN client_permission cp ON gpl.d_id_permission = cp.id_permission
	-- Alias 'gpol' et non 'gp' : 'gp' est déjà pris par group_user_permission ci-dessus.
	LEFT JOIN gpo_group gg ON g.id_group = gg.d_id_group
	LEFT JOIN gpo gpol ON gg.d_id_gpo = gpol.id_gpo
	WHERE g.group_name = ?
	GROUP BY g.id_group, g.group_name, dg.domain_name;
	`

	var group storage.GroupInfo
	var domainName sql.NullString
	var users, userPerms, clients, clientPerms, gpos sql.NullString

	err := db.QueryRow(query, groupName).Scan(
		&group.ID,
		&group.Name,
		&domainName,
		&users,
		&userPerms,
		&clients,
		&clientPerms,
		&gpos,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			logs.Write_LogCode("WARNING", logs.CodeDBGeneric, "database: Aucun groupe trouvé avec le nom : "+groupName)
			return nil, fmt.Errorf("❌ Aucun groupe trouvé avec le nom : %v", groupName)
		}
		logs.WriteLog("db", "❌ Erreur SQL : "+err.Error())
		return nil, fmt.Errorf("erreur lors de l'exécution de la requête : %v", err)
	}

	group.DomainName = domainName.String
	group.Users = splitIfNotEmpty(users.String)
	group.Permissions = splitIfNotEmpty(userPerms.String) // Permissions utilisateurs
	group.Clients = splitIfNotEmpty(clients.String)
	group.ClientPerms = splitIfNotEmpty(clientPerms.String) // Permissions clients/logiciels
	group.GPOs = splitIfNotEmpty(gpos.String)

	return &group, nil
}

// Fonction utilitaire pour transformer une string en slice
func splitIfNotEmpty(s string) []string {
	if s == "" {
		return []string{}
	}
	return splitTrim(s, ", ")
}

// Fonction utilitaire pour split + trim chaque élément
func splitTrim(s, sep string) []string {
	parts := []string{}
	for _, part := range strings.Split(s, sep) {
		parts = append(parts, strings.TrimSpace(part))
	}
	return parts
}

func Command_GET_UsersByGroup(db *sql.DB, groupName string) ([]storage.DisplayUsersByGroup, error) {
	injection := SanitizeIdentifier(groupName)
	if injection != nil {
		return nil, injection
	}
	query := `
		SELECT 
			u.username, 
			COALESCE(DATE_FORMAT(u.date_naissance, '%Y-%m-%d'), '') AS date_naissance, 
			CASE WHEN dl.d_id_user IS NOT NULL THEN TRUE ELSE FALSE END AS is_connected
		FROM users u
		INNER JOIN users_group ug ON u.id_user = ug.d_id_user
		INNER JOIN groups g ON ug.d_id_group = g.id_group
		LEFT JOIN did_login dl ON u.id_user = dl.d_id_user
		WHERE g.group_name = ?
	`

	rows, err := db.Query(query, groupName)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de l'exécution de la requête : "+err.Error())
		return nil, fmt.Errorf("erreur lors de l'exécution de la requête : %v", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
		}
	}()

	var users []storage.DisplayUsersByGroup

	for rows.Next() {
		var user storage.DisplayUsersByGroup
		if err := rows.Scan(&user.Username, &user.DateOfBirth, &user.Connected); err != nil {
			logs.WriteLog("db", "Erreur lors du scan des résultats : "+err.Error())
			return nil, fmt.Errorf("erreur lors du scan des résultats : %v", err)
		}
		users = append(users, user)
	}

	if err = rows.Err(); err != nil {
		logs.WriteLog("db", "Erreur lors de l'itération des résultats : "+err.Error())
		return nil, fmt.Errorf("erreur lors de l'itération des résultats : %v", err)
	}

	if len(users) == 0 {
		logs.Write_LogCode("DEBUG", logs.CodeNone, "database: Aucun utilisateur trouvé pour le groupe : "+groupName)
		return nil, fmt.Errorf("aucun utilisateur trouvé pour le groupe '%s'", groupName)
	}

	return users, nil
}

// Command_GET_UserGroupIDs retourne la liste des ID de groupes pour un username donné
func Command_GET_UserGroupIDs(db *sql.DB, username string) ([]int, error) {
	injection := SanitizeIdentifier(username)
	if injection != nil {
		return nil, injection
	}

	query := `
		SELECT ug.d_id_group
		FROM users_group ug
		INNER JOIN users u ON ug.d_id_user = u.id_user
		WHERE u.username = ?
	`

	rows, err := db.Query(query, username)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de l'exécution de la requête : "+err.Error())
		return nil, fmt.Errorf("erreur lors de l'exécution de la requête : %v", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			logs.Write_Log("ERROR", "Erreur lors de la fermeture des lignes : "+err.Error())
		}
	}()

	var groupIDs []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			logs.WriteLog("db", "Erreur lors du scan des résultats : "+err.Error())
			return nil, fmt.Errorf("erreur lors du scan des résultats : %v", err)
		}
		groupIDs = append(groupIDs, id)
	}

	if err = rows.Err(); err != nil {
		logs.WriteLog("db", "Erreur lors de l'itération des résultats : "+err.Error())
		return nil, fmt.Errorf("erreur lors de l'itération des résultats : %v", err)
	}

	if len(groupIDs) == 0 {
		logs.Write_LogCode("DEBUG", logs.CodeNone, "database: Aucun groupe trouvé pour l'utilisateur : "+username)
		return nil, fmt.Errorf("aucun groupe trouvé pour l'utilisateur '%s'", username)
	}

	return groupIDs, nil
}

// IsUserInGroup indique si un utilisateur appartient à un groupe donné.
//
// Utilisé notamment pour la porte d'entrée superadmin des restrictions GPO
// (voir IsSuperadmin dans protected.go) : l'appartenance est relue en base à
// chaque vérification, jamais mise en cache, pour qu'un retrait du groupe
// prenne effet immédiatement.
func IsUserInGroup(db *sql.DB, username, groupName string) (bool, error) {
	if err := SanitizeIdentifier(username, groupName); err != nil {
		return false, err
	}
	if db == nil {
		return false, fmt.Errorf("connexion base indisponible")
	}
	var count int
	err := db.QueryRow(
		`SELECT COUNT(*) FROM users u
		 INNER JOIN users_group ug ON ug.d_id_user = u.id_user
		 INNER JOIN groups g ON g.id_group = ug.d_id_group
		 WHERE u.username = ? AND g.group_name = ?`,
		username, groupName,
	).Scan(&count)
	if err != nil {
		logs.Write_Log("ERROR", fmt.Sprintf(
			"appartenance %s/%s : vérification échouée : %v", username, groupName, err))
		return false, err
	}
	return count > 0, nil
}
