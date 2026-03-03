package db_permission

import (
	"vaultaire/serveur/logs"
	"database/sql"
	"fmt"
)

// GetUserPermissionID récupère l'id_user_permission à partir du nom
func Command_GET_UserPermissionID(db *sql.DB, name string) (int64, error) {
	var id int64

	query := `SELECT id_user_permission FROM user_permission WHERE name = ? LIMIT 1`
	err := db.QueryRow(query, name).Scan(&id)
	if err != nil {
		if err == sql.ErrNoRows {
			logs.WriteLog("db", "GetUserPermissionID: No permission found with name "+name)
			return 0, fmt.Errorf("aucune permission trouvée avec le nom %s", name)
		}
		return 0, err
	}

	return id, nil
}
