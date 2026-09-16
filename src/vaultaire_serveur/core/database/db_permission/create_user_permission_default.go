package dbpermission

import (
	"database/sql"
)

func CreateUserPermissionDefault(db *sql.DB, name, description string) (int64, error) {
	return CreateUserPermission(db, name, description, "nil", "nil", "nil", "nil", "nil")
}
