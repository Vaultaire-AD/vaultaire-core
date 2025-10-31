package db_permission

import (
	"DUCKY/serveur/database"
	"DUCKY/serveur/logs"
	"fmt"
)

// GetDomainsByGPO récupère tous les domaines associés aux groupes liés à une GPO spécifique
func GetDomainsByGPO(gpoName string) ([]string, error) {
	db := database.GetDatabase()

	query := `
		SELECT DISTINCT dg.domain_name
		FROM linux_gpo_distributions lg
		INNER JOIN group_linux_gpo glg ON lg.id = glg.d_id_gpo
		INNER JOIN groups g ON g.id_group = glg.d_id_group
		INNER JOIN domain_group dg ON dg.d_id_group = g.id_group
		WHERE lg.gpo_name = ?
	`

	rows, err := db.Query(query, gpoName)
	if err != nil {
		logs.Write_Log("ERROR", fmt.Sprintf("Erreur récupération des domaines pour la GPO '%s' : %v", gpoName, err))
		return nil, err
	}
	defer rows.Close()

	var domains []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			logs.Write_Log("ERROR", fmt.Sprintf("Erreur scan des domaines pour la GPO '%s' : %v", gpoName, err))
			return nil, err
		}
		domains = append(domains, domain)
	}

	if len(domains) == 0 {
		logs.Write_Log("DEBUG", fmt.Sprintf("Aucun domaine trouvé pour la GPO '%s'", gpoName))
	}

	return domains, nil
}
