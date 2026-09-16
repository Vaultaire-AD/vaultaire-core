package dbldap

import (
	"database/sql"
	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
)

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
