package dbpermission

import (
	"database/sql"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
)

func Command_GET_AllUserPermissions(db *sql.DB) ([]storage.UserPermission, error) {
	var permissions []storage.UserPermission

	query := `
        SELECT id_user_permission, name, description, none, auth, compare, search, web_admin
        FROM user_permission
    `

	rows, err := db.Query(query)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"Erreur lors de la récupération des permissions utilisateurs : "+err.Error())
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
			logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"Erreur lors du scan des résultats des permissions utilisateurs : "+err.Error())
			return nil, err
		}
		permissions = append(permissions, perm)
	}

	// rows.Err() distingue « la lecture est terminée » de « la lecture s'est
	// interrompue ». Sans ce contrôle, une coupure en cours d'itération rend un
	// résultat PARTIEL présenté comme complet.
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return permissions, nil
}
