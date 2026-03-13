package database

import "database/sql"

func CreateGPO(db *sql.DB, name, ubuntu, debian, rocky string) (int, error) {
	query := `INSERT INTO linux_gpo_distributions (gpo_name, ubuntu, debian, rocky) 
			VALUES (?, ?, ?, ?)`
	result, err := db.Exec(query, name, ubuntu, debian, rocky)
	if err != nil {
		return 0, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}

	return int(id), nil
}
