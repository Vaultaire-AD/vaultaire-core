package dbpermission

import (
	"database/sql"
	"fmt"
	"vaultaire/core/database"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
)

func CreateUserPermissionDefault(db *sql.DB, name, description string) (int64, error) {
	return CreateUserPermission(db, name, description, "nil", "nil", "nil", "nil", "nil")
}

// Création d'une permission utilisateur dans user_permission (RBAC: actions granulaires dans user_permission_action)
func CreateUserPermission(db *sql.DB, name, description string, none, web_admin, auth, compare, search string) (int64, error) {
	result, err := db.Exec(`
		INSERT INTO user_permission (name, description, none, web_admin, auth, compare, search)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		name, description, none, web_admin, auth, compare, search,
	)
	if err != nil {
		logs.WriteLog("db", "erreur lors de l'insertion de la permission utilisateur CreateUserPermission : "+err.Error())
		return 0, fmt.Errorf("erreur lors de l'insertion de la permission utilisateur : %v", err)
	}

	permissionID, err := result.LastInsertId()
	if err != nil {
		logs.WriteLog("db", "erreur lors de la récupération de l'ID de la permission utilisateur CreateUserPermission : "+err.Error())
		return 0, fmt.Errorf("erreur lors de la récupération de l'ID de la permission utilisateur : %v", err)
	}

	return permissionID, nil
}

func Command_DELETE_UserPermissionByName(db *sql.DB, permissionName string) error {
	injection := database.SanitizeIdentifier(permissionName)
	if injection != nil {
		return injection
	}
	// La permission complète du groupe superadmin n'est pas supprimable :
	// voir core/database/protected.go.
	if err := database.GuardProtectedUserPermissionDeletion(permissionName); err != nil {
		return err
	}
	query := `DELETE FROM user_permission WHERE name = ?`
	_, err := db.Exec(query, permissionName)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la suppression de la permission utilisateur : "+err.Error())
		return fmt.Errorf("erreur lors de la suppression de la permission utilisateur %s : %v", permissionName, err)
	}
	logs.Write_LogCode("DEBUG", logs.CodeNone, fmt.Sprintf("database: Permission utilisateur %s supprimée avec succès", permissionName))
	return nil
}

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

	// rows.Err() distingue « la lecture est terminée » de « la lecture s'est
	// interrompue ». Sans ce contrôle, une coupure en cours d'itération rend un
	// résultat PARTIEL présenté comme complet.
	if err := rows.Err(); err != nil {
		return nil, err
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

// GetUserPermissionID récupère l'id_user_permission à partir du nom
func Command_GET_UserPermissionID(db *sql.DB, name string) (int64, error) {
	id, found, err := database.LookupUserPermissionID(db, name)
	if err != nil {
		return 0, err
	}
	if !found {
		logs.Write_LogCode("DEBUG", logs.CodeNone, "database: GetUserPermissionID: No permission found with name "+name)
		return 0, fmt.Errorf("aucune permission trouvée avec le nom %s", name)
	}

	return int64(id), nil
}

// Command_GET_UserPermissionNamesByUsername returns permission names the user gets through their groups.
func Command_GET_UserPermissionNamesByUsername(db *sql.DB, username string) ([]string, error) {
	if err := database.SanitizeIdentifier(username); err != nil {
		return nil, err
	}
	query := `
		SELECT DISTINCT p.name
		FROM user_permission p
		INNER JOIN group_user_permission gup ON p.id_user_permission = gup.d_id_user_permission
		INNER JOIN users_group ug ON gup.d_id_group = ug.d_id_group
		INNER JOIN users u ON ug.d_id_user = u.id_user
		WHERE u.username = ?
	`
	rows, err := db.Query(query, username)
	if err != nil {
		logs.WriteLog("db", "UserPermissionNamesByUsername: "+err.Error())
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		names = append(names, n)
	}
	return names, rows.Err()
}
