package db_permission

import (
	"vaultaire/serveur/logs"
	"vaultaire/serveur/storage"
	"database/sql"
)

func Command_GET_AllUserPermissions(db *sql.DB) ([]storage.UserPermission, error) {
	var permissions []storage.UserPermission

	query := `
        SELECT id_user_permission, name, description, none, auth, compare, search, web_admin
        FROM user_permission
    `

	rows, err := db.Query(query)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la récupération des permissions utilisateurs : "+err.Error())
		return nil, err
	}
	defer func() {
		if err := rows.Close(); err != nil {
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
			&perm.Web_admin,
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
		SELECT id_user_permission, name, description, none, auth, compare, search, web_admin
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
		&permission.Web_admin,
	)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la récupération de la permission utilisateur par nom : "+err.Error())
		return nil, err
	}

	return &permission, nil
}
