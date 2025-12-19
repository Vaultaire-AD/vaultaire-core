package database

import (
	"DUCKY/serveur/logs"
	"DUCKY/serveur/storage"
	"database/sql"
	"fmt"
)

func GetAllGroupsWithDomains(db *sql.DB) ([]storage.GroupDomain, error) {
	query := `
		SELECT 
			g.group_name, 
			dg.domain_name
		FROM 
			groups g
		JOIN 
			domain_group dg ON g.id_group = dg.d_id_group
	`

	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("erreur lors de l'exécution de la requête : %v", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
		}
	}()

	var results []storage.GroupDomain
	for rows.Next() {
		var gd storage.GroupDomain
		if err := rows.Scan(&gd.GroupName, &gd.DomainName); err != nil {
			return nil, fmt.Errorf("erreur lors du scan : %v", err)
		}
		results = append(results, gd)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("erreur d'itération : %v", err)
	}

	return results, nil
}
