package dbpermission

import (
	"database/sql"
	"fmt"
	"vaultaire/core/logs"
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
