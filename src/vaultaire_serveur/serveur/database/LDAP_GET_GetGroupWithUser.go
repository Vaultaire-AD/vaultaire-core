package database

import (
	ldapstorage "DUCKY/serveur/ldap/LDAP_Storage"
	"DUCKY/serveur/logs"
	"database/sql"
	"fmt"
)

// fetchGroupAndUsersDataByGroupName exécute la requête SQL pour récupérer les informations
// d'un seul groupe et de ses utilisateurs.
// Elle retourne un *sql.Rows qui contient les lignes du groupe donné,
// ou une erreur. L'appelant est responsable de fermer les lignes.
func fetchGroupAndUsersDataByGroupName(db *sql.DB, groupName string) (*sql.Rows, error) {
	if groupName == "" {
		return nil, fmt.Errorf("groupName cannot be empty for database query")
	}

	query := `
    SELECT g.group_name, dg.domain_name, u.username
    FROM groups g
    JOIN domain_group dg ON dg.d_id_group = g.id_group
    JOIN users_group ug ON ug.d_id_group = g.id_group
    JOIN users u ON u.id_user = ug.d_id_user
    WHERE g.group_name = ?
    ORDER BY g.group_name, dg.domain_name
    `
	// Utilisez QueryContext ou Query pour une requête simple avec un seul argument
	rows, err := db.Query(query, groupName)
	if err != nil {
		return nil, fmt.Errorf("failed to query database for group '%s': %w", groupName, err)
	}
	// L'appelant (ou processGroupRowsFromSingleQuery) est responsable de rows.Close()

	return rows, nil
}

// processGroupRowsFromSingleQuery traite les résultats d'une requête pour un seul groupe.
// Elle retourne un pointeur vers un ldapstorage.Group si des données sont trouvées,
// ou nil si le groupe n'existe pas ou s'il y a une erreur.
// Elle ferme automatiquement les *sql.Rows.
func processGroupRowsFromSingleQuery(rows *sql.Rows) (*ldapstorage.Group, error) {
	defer func() {
		if err := rows.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
		}
	}() // Assurez-vous que les lignes sont toujours fermées

	var currentGroup *ldapstorage.Group // Pointeur pour le groupe en cours de construction

	for rows.Next() {
		var groupName, domainName, username string
		if err := rows.Scan(&groupName, &domainName, &username); err != nil {
			return nil, fmt.Errorf("failed to scan row for group data: %w", err)
		}

		// Initialise le groupe si c'est la première ligne
		if currentGroup == nil {
			currentGroup = &ldapstorage.Group{
				GroupName:  groupName,
				DomainName: domainName,
				Users:      []string{}, // Initialise la liste des utilisateurs
			}
		}
		// S'assure que le groupe correspond bien (utile si la requête n'était pas assez ciblée, mais ici elle l'est)
		if currentGroup.GroupName != groupName || currentGroup.DomainName != domainName {
			// Cela ne devrait normalement pas arriver avec la requête actuelle qui cible un seul groupe/domaine
			// mais c'est une vérification de robustesse.
			return nil, fmt.Errorf("inconsistent data for single group query: expected %s|%s, got %s|%s",
				currentGroup.GroupName, currentGroup.DomainName, groupName, domainName)
		}

		currentGroup.Users = append(currentGroup.Users, username)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error after iterating rows for single group: %w", err)
	}

	return currentGroup, nil // Retourne le groupe construit (nil si aucune ligne)
}

// GetGroupsWithUsersByNames est la fonction principale qui orchestre
// la récupération des données de plusieurs groupes en appelant la fonction
// de requête individuelle pour chaque nom de groupe.
func GetGroupsWithUsersByNames(db *sql.DB, groupNames []string) ([]ldapstorage.Group, error) {
	if len(groupNames) == 0 {
		return []ldapstorage.Group{}, nil // Retourne un slice vide si aucun nom de groupe n'est fourni
	}

	var allFoundGroups []ldapstorage.Group // Slice pour stocker tous les groupes trouvés

	for _, name := range groupNames {
		// Étape 1: Exécuter la requête SQL pour UN SEUL groupe
		rows, err := fetchGroupAndUsersDataByGroupName(db, name)
		if err != nil {
			// Décidez comment gérer les erreurs pour des groupes individuels.
			// Ici, on retourne l'erreur. Vous pourriez vouloir la loguer et continuer.
			return nil, err
		}

		// Étape 2: Traiter les résultats de cette requête spécifique
		group, err := processGroupRowsFromSingleQuery(rows)
		if err != nil {
			return nil, err
		}

		if group != nil { // Si des données pour ce groupe ont été trouvées
			allFoundGroups = append(allFoundGroups, *group)
		}
	}

	return allFoundGroups, nil
}

// GetGroupWithUsersByName récupère un groupe spécifique et ses utilisateurs.
func GetGroupWithUsersByName(db *sql.DB, groupName string) (*ldapstorage.Group, error) {
	rows, err := fetchGroupAndUsersDataByGroupName(db, groupName)
	if err != nil {
		// Décidez comment gérer les erreurs pour des groupes individuels.
		// Ici, on retourne l'erreur. Vous pourriez vouloir la loguer et continuer.
		return nil, err
	}

	// Étape 2: Traiter les résultats de cette requête spécifique
	group, err := processGroupRowsFromSingleQuery(rows)
	if err != nil {
		return nil, err
	}
	return group, nil
}
