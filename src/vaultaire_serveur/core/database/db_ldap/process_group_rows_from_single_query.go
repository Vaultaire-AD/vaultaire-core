package dbldap

import (
	"database/sql"
	"fmt"
	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
	"vaultaire/core/logs"
)

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
