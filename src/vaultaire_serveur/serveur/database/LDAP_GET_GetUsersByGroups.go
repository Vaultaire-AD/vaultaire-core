package database

import (
	ldapstorage "DUCKY/serveur/ldap/LDAP_Storage"
	"DUCKY/serveur/logs"
	"database/sql"
)

// GetUsersByGroups récupère les utilisateurs appartenant à plusieurs groupes spécifiés.
func GetUsersByGroups(groups []string, db *sql.DB) ([]ldapstorage.User, error) {
	if len(groups) == 0 {
		return []ldapstorage.User{}, nil
	}

	var allUsers []ldapstorage.User
	seen := make(map[string]bool) // pour éviter les doublons

	for _, group := range groups {
		users, err := GetUsersByGroup(group, db)
		if err != nil {
			return nil, err
		}

		for _, user := range users {
			if !seen[user.Username] {
				allUsers = append(allUsers, user)
				seen[user.Username] = true
			}
		}
	}

	return allUsers, nil
}

// GetUsersByGroup récupère les utilisateurs appartenant à un groupe spécifié.
func GetUsersByGroup(group string, db *sql.DB) ([]ldapstorage.User, error) {
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
		WHERE g.group_name = ?
		GROUP BY u.id_user, u.username, u.created_at
	`

	rows, err := db.Query(query, group)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := rows.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
		}
	}()

	var users []ldapstorage.User
	for rows.Next() {
		var user ldapstorage.User
		if err := rows.Scan(&user.ID, &user.Username, &user.Firstname, &user.Lastname, &user.Email, &user.Created_at, &user.GroupDomain); err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	return users, nil
}

// GetUserByUsername récupère un utilisateur par son nom d'utilisateur.
func GetUserByUsername(username string, db *sql.DB) (ldapstorage.User, error) {
	injection := SanitizeInput(username)
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
