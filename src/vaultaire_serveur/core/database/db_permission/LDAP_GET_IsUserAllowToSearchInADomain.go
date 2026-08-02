package db_permission

import (
	"database/sql"
	"log"
	"vaultaire/core/database"
)

// GetUserPermissionsForAction récupère toutes les valeurs d'action d'un utilisateur
func GetUserPermissionsForAction(db *sql.DB, username, action string) ([]string, error) {
	injection := database.SanitizeIdentifier(username, action)
	if injection != nil {
		return nil, nil
	}

	query := `
		SELECT up.` + action + `
		FROM users u
		JOIN users_group ug ON u.id_user = ug.d_id_user
		JOIN group_user_permission gup ON ug.d_id_group = gup.d_id_group
		JOIN user_permission up ON gup.d_id_user_permission = up.id_user_permission
		WHERE u.username = ?
	`

	rows, err := db.Query(query, username)
	if err != nil {
		log.Printf("Erreur SQL : %v", err)
		return nil, err
	}
	defer rows.Close()

	var results []string
	for rows.Next() {
		var rawValue string
		if err := rows.Scan(&rawValue); err != nil {
			log.Printf("Erreur Scan : %v", err)
			continue
		}
		results = append(results, rawValue)
	}

	// rows.Err() distingue « la lecture est terminée » de « la lecture s'est
	// interrompue ». Sans ce contrôle, une coupure en cours d'itération rend un
	// résultat PARTIEL présenté comme complet.
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return results, nil
}
