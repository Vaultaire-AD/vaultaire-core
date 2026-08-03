package database

import (
	"database/sql"
	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
	"vaultaire/core/logs"
)

// GetUsersByGroups (au pluriel) a été supprimée : aucun appelant.
//
// Elle bouclait sur GetUsersByGroup en dédoublonnant par nom d'utilisateur —
// donc N requêtes pour N groupes. Si le besoin revient, il vaudra mieux une
// seule requête avec une clause IN qu'une boucle : c'est la même donnée en un
// aller-retour au lieu de N.

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

	// rows.Err() distingue « la lecture est terminée » de « la lecture s'est
	// interrompue ». Sans ce contrôle, une coupure en cours d'itération rend un
	// résultat PARTIEL présenté comme complet.
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return users, nil
}

// GetUserByUsername récupère un utilisateur par son nom d'utilisateur.
func GetUserByUsername(username string, db *sql.DB) (ldapstorage.User, error) {
	injection := SanitizeIdentifier(username)
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
