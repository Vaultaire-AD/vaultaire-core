package database

import (
	"DUCKY/serveur/logs"
	"DUCKY/serveur/storage"
	"database/sql"
)

// Récupère toutes les permissions
func Command_GET_AllClientPermissions(db *sql.DB) ([]storage.ClientPermission, error) {
	var permissions []storage.ClientPermission

	query := `
	SELECT 
		id_permission,
		name_permission,
		is_admin
	FROM client_permission
	`

	rows, err := db.Query(query)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la récupération des permissions clients : "+err.Error())
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var permission storage.ClientPermission
		if err := rows.Scan(&permission.ID, &permission.Name, &permission.IsAdmin); err != nil {
			logs.WriteLog("db", "Erreur lors du scan des permissions clients : "+err.Error())
			return nil, err
		}
		permissions = append(permissions, permission)
	}

	return permissions, nil
}

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
