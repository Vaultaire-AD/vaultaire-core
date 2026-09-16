package dbsessions

import (
	"database/sql"
	"time"
)

func RefreshSessionValidity(db *sql.DB, sessionKey []byte) error {

	expiration := time.Now().Add(10 * time.Minute)
	formattedTime := expiration.Format("2006/01/02 15:04:05")

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
