package database

import (
	"DUCKY/serveur/storage"
	"database/sql"
)

func Command_GET_GPOInfoByName(db *sql.DB, gpoName string) (storage.LinuxGPO, error) {
	var gpo storage.LinuxGPO
	query := `SELECT id, gpo_name, ubuntu, debian, rocky 
			  FROM linux_gpo_distributions 
			  WHERE gpo_name = ?`
	err := db.QueryRow(query, gpoName).Scan(&gpo.ID, &gpo.GPOName, &gpo.Ubuntu, &gpo.Debian, &gpo.Rocky)
	if err != nil {
		return gpo, err
	}
	return gpo, nil
}
