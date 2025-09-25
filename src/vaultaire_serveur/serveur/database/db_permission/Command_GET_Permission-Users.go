package database

import (
	"DUCKY/serveur/logs"
	"DUCKY/serveur/storage"
	"database/sql"
)

func Command_GET_AllUserPermissions(db *sql.DB) ([]storage.UserPermission, error) {
	var permissions []storage.UserPermission

	query := `
        SELECT 
            id_user_permission, 
            name, 
            description, 
            none, 
            auth, 
            compare, 
            search, 
            can_read, 
            can_write
        FROM user_permission
    `

	rows, err := db.Query(query)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la récupération des permissions utilisateurs : "+err.Error())
		return nil, err
	}
	defer func() {
		if err := rows.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
		}
	}()

	for rows.Next() {
		var perm storage.UserPermission
		if err := rows.Scan(
			&perm.ID,
			&perm.Name,
			&perm.Description,
			&perm.None,
			&perm.Auth,
			&perm.Compare,
			&perm.Search,
			&perm.Read,
			&perm.Write,
		); err != nil {
			logs.WriteLog("db", "Erreur lors du scan des résultats des permissions utilisateurs : "+err.Error())
			return nil, err
		}
		permissions = append(permissions, perm)
	}

	return permissions, nil
}

func Command_GET_UserPermissionByName(db *sql.DB, name string) (*storage.UserPermission, error) {
	query := `
		SELECT 
			id_user_permission, 
			name, 
			description, 
			none, 
			auth, 
			compare, 
			search, 
			can_read, 
			can_write,
			api_read_permission,
			api_write_permission,
			web_admin
		FROM user_permission
		WHERE name = ?
		LIMIT 1
	`

	var permission storage.UserPermission
	err := db.QueryRow(query, name).Scan(
		&permission.ID,
		&permission.Name,
		&permission.Description,
		&permission.None,
		&permission.Auth,
		&permission.Compare,
		&permission.Search,
		&permission.Read,
		&permission.Write,
		&permission.APIRead,
		&permission.APIWrite,
		&permission.Web_admin,
	)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la récupération de la permission utilisateur par nom : "+err.Error())
		return nil, err
	}

	return &permission, nil
}
