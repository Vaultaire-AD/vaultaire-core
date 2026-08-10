package dbpermission

import (
	"database/sql"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
)

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
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"Erreur lors de la récupération de la permission utilisateur par nom : "+err.Error())
		return nil, err
	}

	return &permission, nil
}
