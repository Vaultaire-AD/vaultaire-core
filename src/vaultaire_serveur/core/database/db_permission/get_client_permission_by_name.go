package dbpermission

import (
	"database/sql"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
)

func Command_GET_ClientPermissionByName(db *sql.DB, name string) (*storage.ClientPermission, error) {
	query := `
		SELECT cp.id_permission, cp.name_permission, cp.is_admin
		FROM client_permission cp
		WHERE cp.name_permission = ?
		LIMIT 1
	`

	var permission storage.ClientPermission
	err := db.QueryRow(query, name).Scan(&permission.ID, &permission.Name, &permission.IsAdmin)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la récupération de la permission client par nom : "+err.Error())
		return nil, err
	}

	return &permission, nil
}
