package dbpermission

import (
	"database/sql"
	"fmt"
	"vaultaire/core/logs"
)

// Création d'une permission utilisateur dans user_permission (RBAC: actions granulaires dans user_permission_action)
func CreateUserPermission(db *sql.DB, name, description string, none, web_admin, auth, compare, search string) (int64, error) {
	result, err := db.Exec(`
		INSERT INTO user_permission (name, description, none, web_admin, auth, compare, search)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		name, description, none, web_admin, auth, compare, search,
	)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"erreur lors de l'insertion de la permission utilisateur CreateUserPermission : "+err.Error())
		return 0, fmt.Errorf("erreur lors de l'insertion de la permission utilisateur : %v", err)
	}

	permissionID, err := result.LastInsertId()
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"erreur lors de la récupération de l'ID de la permission utilisateur CreateUserPermission : "+err.Error())
		return 0, fmt.Errorf("erreur lors de la récupération de l'ID de la permission utilisateur : %v", err)
	}

	return permissionID, nil
}
