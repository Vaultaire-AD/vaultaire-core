package dbpermission

import (
	"database/sql"
)

// getPermissionNameByID résout le nom d'une permission depuis son identifiant.
//
// Une erreur (permission absente) n'est pas traitée comme un refus par
// l'appelant : l'écriture qui suit échouera de toute façon sur une permission
// inexistante, et bloquer ici masquerait la vraie cause.
func getPermissionNameByID(db *sql.DB, id int64) (string, error) {
	var name string
	err := db.QueryRow(
		"SELECT name FROM user_permission WHERE id_user_permission = ? LIMIT 1", id,
	).Scan(&name)
	return name, err
}
