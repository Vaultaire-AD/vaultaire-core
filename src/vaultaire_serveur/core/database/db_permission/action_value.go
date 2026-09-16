package dbpermission

import (
	"database/sql"
)

// actionValue lit une action RBAC dans user_permission_action.
//
// L'absence de ligne rend "nil" et non une erreur : une action jamais renseignée
// vaut « pas accordée », qui est l'état par défaut de toute permission neuve.
func actionValue(db *sql.DB, permissionID int64, action string) (string, error) {
	var value string
	err := db.QueryRow(
		"SELECT value FROM user_permission_action WHERE id_user_permission = ? AND action_key = ?",
		permissionID, action,
	).Scan(&value)
	if err == sql.ErrNoRows {
		return "nil", nil
	}
	if err != nil {
		return "", err
	}
	return value, nil
}
