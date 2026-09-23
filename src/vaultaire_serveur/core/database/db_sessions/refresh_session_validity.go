package dbsessions

import (
	"database/sql"
)

func RefreshSessionValidity(db *sql.DB, sessionKey []byte) error {

	formattedTime := EcheanceSession()

	query := `
		UPDATE did_login
		SET key_time_validity = ?
		WHERE session_key = ?
	`

	_, err := db.Exec(
		query,
		formattedTime,
		sessionKey,
	)

	return err
}
