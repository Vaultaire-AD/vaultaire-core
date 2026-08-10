package dbpermission

import (
	"database/sql"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
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
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"Erreur lors de la récupération des permissions clients : "+err.Error())
		return nil, err
	}
	defer func() {
		if err := rows.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
		}
	}()
	for rows.Next() {
		var permission storage.ClientPermission
		if err := rows.Scan(&permission.ID, &permission.Name, &permission.IsAdmin); err != nil {
			logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"Erreur lors du scan des permissions clients : "+err.Error())
			return nil, err
		}
		permissions = append(permissions, permission)
	}

	// rows.Err() distingue « la lecture est terminée » de « la lecture s'est
	// interrompue ». Sans ce contrôle, une coupure en cours d'itération rend un
	// résultat PARTIEL présenté comme complet.
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return permissions, nil
}
