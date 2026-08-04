package dbldap

import (
	"database/sql"
	database "vaultaire/core/database"
	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
)

// GetUserByUsername récupère un utilisateur par son nom d'utilisateur.
func GetUserByUsername(username string, db *sql.DB) (ldapstorage.User, error) {
	injection := database.SanitizeIdentifier(username)
	if injection != nil {
		return ldapstorage.User{}, injection
	}
	var user ldapstorage.User

	query := `
		SELECT 
			u.id_user, 
			u.username,
			u.firstname,
			u.lastname,
			u.email, 
			u.created_at, 
			MIN(dg.domain_name) as domain_name
		FROM users u
		JOIN users_group ug ON u.id_user = ug.d_id_user
		JOIN groups g ON ug.d_id_group = g.id_group
		JOIN domain_group dg ON dg.d_id_group = g.id_group
		WHERE u.username = ?
		GROUP BY u.id_user, u.username, u.created_at
		LIMIT 1
	`

	row := db.QueryRow(query, username)
	err := row.Scan(&user.ID, &user.Username, &user.Firstname, &user.Lastname, &user.Email, &user.Created_at, &user.GroupDomain)
	if err != nil {
		return ldapstorage.User{}, err
	}

	return user, nil
}
