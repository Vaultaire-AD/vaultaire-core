package database

import (
	"database/sql"
	"fmt"
)

func Get_PublicKeys_ByUserID(db *sql.DB, userID int) ([]string, error) {
	query := `SELECT public_key FROM user_public_keys WHERE id_user = ?`

	rows, err := db.Query(query, userID)
	if err != nil {
		return nil, fmt.Errorf("erreur requête DB: %w", err)
	}
	defer rows.Close()

	var keys []string

	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, fmt.Errorf("erreur scan clé publique: %w", err)
		}
		keys = append(keys, key)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("erreur itération rows: %w", err)
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("aucune clé publique pour l'utilisateur %d", userID)
	}

	return keys, nil
}
