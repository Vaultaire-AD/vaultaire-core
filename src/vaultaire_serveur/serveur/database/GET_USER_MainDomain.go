package database

import (
	"vaultaire/serveur/logs"
	"database/sql"
	"errors"
	"strings"
)

// Récupère les domaines associés aux groupes utilisateur
func GetDomainsForUser(db *sql.DB, userID int) ([]string, error) {
	query := `
		SELECT DISTINCT dg.domain_name
		FROM domain_group dg
		JOIN groups g ON dg.d_id_group = g.id_group
		JOIN users_group ug ON ug.d_id_group = g.id_group
		WHERE ug.d_id_user = ?
	`

	rows, err := db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := rows.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
		}
	}()

	var domains []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return nil, err
		}
		domains = append(domains, domain)
	}
	return domains, nil
}

// Récupérer le domaine principal, ex: company.com à partir de finance.company.com
func ExtractMainDomain(domain string) (string, error) {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return "", errors.New("domaine invalide")
	}
	n := len(parts)
	return parts[n-2] + "." + parts[n-1], nil
}

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
