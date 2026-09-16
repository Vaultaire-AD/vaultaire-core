package database

import (
	"database/sql"
)

func GetDatabase() *sql.DB {
	return DB
}
