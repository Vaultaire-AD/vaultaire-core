package database

import (
	"DUCKY/serveur/logs"
	"database/sql"
	"fmt"
	"strings"
)

// FindUserDomainFromGroups recherche le domaine utilisateur en fonction des groupes auxquels il appartient.
func FindUserDomainFromGroups(uid string, baseDomain string, db *sql.DB) (string, error) {
	injection := SanitizeInput(uid, baseDomain)
	if injection != nil {
		return "", injection
	}
	query := `
		SELECT dg.domain_name
		FROM users u
		JOIN users_group ug ON u.id_user = ug.d_id_user
		JOIN groups g ON g.id_group = ug.d_id_group
		JOIN domain_group dg ON dg.d_id_group = g.id_group
		WHERE u.username = ?;
	`
	rows, err := db.Query(query, uid)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := rows.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
		}
	}()

	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return "", err
		}
		if strings.HasSuffix(domain, baseDomain) {
			return domain, nil // 🟢 Domaine accepté car dans la sous-forêt
		}
	}
	return "", fmt.Errorf("aucun domaine trouvé sous la forêt '%s' pour l'utilisateur '%s'", baseDomain, uid)
}
