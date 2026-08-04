package dbpermission

import (
	"database/sql"
	"fmt"
	"vaultaire/core/database"
	"vaultaire/core/logs"
)

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
