package database

import (
	"DUCKY/serveur/logs"
	"database/sql"
	"fmt"
	"strings"
)

// GetGroupIDsFromDomains prend une liste de domaines complets et renvoie les ID de groupes correspondants
func GetGroupIDsFromDomains(db *sql.DB, domains []string) ([]int, error) {
	if len(domains) == 0 {
		return nil, nil
	}

	// Préparer la clause IN pour la requête
	placeholders := make([]string, len(domains))
	args := make([]interface{}, len(domains))
	for i, d := range domains {
		placeholders[i] = "?"
		args[i] = d
	}

	query := fmt.Sprintf(`
		SELECT g.id_group
		FROM groups g
		INNER JOIN domain_group dg ON dg.d_id_group = g.id_group
		WHERE dg.domain_name IN (%s)
	`,
		// "?, ?, ?" selon la taille de domains
		strings.Join(placeholders, ","),
	)

	rows, err := db.Query(query, args...)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la récupération des groupes depuis les domaines : "+err.Error())
		return nil, fmt.Errorf("erreur SQL : %v", err)
	}
	defer rows.Close()

	var groupIDs []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			logs.WriteLog("db", "Erreur lors du scan des IDs de groupe : "+err.Error())
			return nil, fmt.Errorf("erreur lors du scan : %v", err)
		}
		groupIDs = append(groupIDs, id)
	}

	if err = rows.Err(); err != nil {
		logs.WriteLog("db", "Erreur d’itération : "+err.Error())
		return nil, fmt.Errorf("erreur d’itération : %v", err)
	}

	return groupIDs, nil
}
