package dbdomains

import (
	"database/sql"
	"vaultaire/core/logs"
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
	// rows.Err() distingue « la lecture est terminée » de « la lecture s'est
	// interrompue ». Sans ce contrôle, une coupure en cours d'itération rend un
	// résultat PARTIEL présenté comme complet.
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return domains, nil
}
