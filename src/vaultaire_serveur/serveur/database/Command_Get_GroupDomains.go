package database

import (
	"DUCKY/serveur/logs"
	"database/sql"
	"fmt"
)

// Command_GET_DomainsFromGroupIDs récupère les domaines associés à une liste d'ID de groupes.
// Comme un groupe ne peut avoir qu'un seul domaine, on retourne une slice de string correspondante.
func Command_GET_DomainsFromGroupIDs(db *sql.DB, groupIDs []int) ([]string, error) {
	if len(groupIDs) == 0 {
		return []string{}, nil
	}

	domains := []string{}
	for _, id := range groupIDs {
		var domain string
		err := db.QueryRow(`SELECT domain_name FROM domain_group WHERE d_id_group = ? LIMIT 1`, id).Scan(&domain)
		if err != nil {
			if err == sql.ErrNoRows {
				// Pas de domaine pour ce groupe, on peut ignorer
				continue
			}
			return nil, fmt.Errorf("erreur lors de la récupération du domaine pour le groupe %d : %v", id, err)
		}
		domains = append(domains, domain)
	}

	return domains, nil
}

func GetDomainsFromGroupName(groupName string) ([]string, error) {
	db := GetDatabase()

	// On récupère l'ID du groupe via son nom
	groupID, err := GetGroupIDByName(db, groupName)
	if err != nil {
		logs.Write_Log("WARNING", "Erreur récupération ID du groupe "+groupName+" : "+err.Error())
		return nil, err
	}

	// On récupère les domaines associés à ce groupe
	domains, err := Command_GET_DomainsFromGroupIDs(db, []int{groupID})
	if err != nil {
		logs.Write_Log("WARNING", "Erreur récupération domaines du groupe "+groupName+" : "+err.Error())
		return nil, err
	}

	return domains, nil
}
