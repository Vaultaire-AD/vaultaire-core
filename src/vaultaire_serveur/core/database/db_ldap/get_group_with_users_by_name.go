package dbldap

import (
	"database/sql"
	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
)

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
