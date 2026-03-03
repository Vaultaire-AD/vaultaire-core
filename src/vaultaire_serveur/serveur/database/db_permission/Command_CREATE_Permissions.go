package db_permission

import (
	"vaultaire/serveur/logs"
	"database/sql"
	"fmt"
)

func CreateClientPermission(db *sql.DB, permissionName string, isAdmin bool) (int64, error) {
	result, err := db.Exec(`INSERT INTO client_permission (name_permission, is_admin) VALUES (?, ?)`, permissionName, isAdmin)
	if err != nil {
		logs.WriteLog("db", "erreur lors de l'insertion de la permission client CreateClientPermission : "+err.Error())
		return 0, fmt.Errorf("erreur lors de l'insertion de la permission client : %v", err)
	}

	permissionID, err := result.LastInsertId()
	if err != nil {
		logs.WriteLog("db", "erreur lors de la récupération de l'ID de la permission client CreateClientPermission : "+err.Error())
		return 0, fmt.Errorf("erreur lors de la récupération de l'ID de la permission client : %v", err)
	}

	return permissionID, nil
}

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
