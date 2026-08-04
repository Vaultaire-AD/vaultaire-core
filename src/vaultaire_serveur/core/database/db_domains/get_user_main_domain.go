package dbdomains

import (
	"database/sql"
	"errors"
)

// Fonction principale qui récupère le domaine principal d’un utilisateur (le premier trouvé)
func GetUserMainDomain(db *sql.DB, userID int) (string, error) {
	domains, err := GetDomainsForUser(db, userID)
	if err != nil {
		return "", err
	}
	if len(domains) == 0 {
		return "", errors.New("aucun domaine trouvé pour l'utilisateur")
	}

	// Ici on prend le premier domaine associé
	return ExtractMainDomain(domains[0])
}
