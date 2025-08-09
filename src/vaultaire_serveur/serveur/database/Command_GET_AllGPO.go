package database

import (
	"DUCKY/serveur/storage"
	"database/sql"
	"log"
)

// GetAllGPOs récupère toutes les GPO depuis la base de données
func Command_GET_AllGPO(db *sql.DB) ([]*storage.LinuxGPO, error) {
	query := "SELECT id, gpo_name, ubuntu, debian, rocky FROM linux_gpo_distributions"
	rows, err := db.Query(query)
	if err != nil {
		log.Println("Erreur lors de la récupération des GPO:", err)
		return nil, err
	}
	defer rows.Close()

	var gpos []*storage.LinuxGPO
	for rows.Next() {
		var gpo storage.LinuxGPO
		if err := rows.Scan(&gpo.ID, &gpo.GPOName, &gpo.Ubuntu, &gpo.Debian, &gpo.Rocky); err != nil {
			log.Println("Erreur lors du scan des lignes de GPO:", err)
			return nil, err
		}
		gpos = append(gpos, &gpo)
	}

	if err := rows.Err(); err != nil {
		log.Println("Erreur de ligne:", err)
		return nil, err
	}

	return gpos, nil
}
