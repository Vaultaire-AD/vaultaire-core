package db_permission

import (
	"DUCKY/serveur/database"
	"database/sql"
	"log"
)

func IsUserAuthorizedToSearch(db *sql.DB, username, domain string) bool {
	injection := database.SanitizeInput(username, domain)
	if injection != nil {
		return false
	}
	query := `
		SELECT 1
		FROM users u
		JOIN users_group ug ON u.id_user = ug.d_id_user
		JOIN domain_group dg ON ug.d_id_group = dg.d_id_group
		JOIN group_user_permission gup ON ug.d_id_group = gup.d_id_group
		JOIN user_permission up ON gup.d_id_user_permission = up.id_user_permission
		WHERE u.username = ?
		  AND dg.domain_name = ?
		  AND up.search = TRUE
		LIMIT 1
	`
	var exists int
	err := db.QueryRow(query, username, domain).Scan(&exists)
	if err != nil {
		if err == sql.ErrNoRows {
			return false
		}
		log.Printf("Erreur SQL : %v", err)
		return false
	}
	return true
}
