package dbcertificates

import (
	"time"
)

// parseMySQLDateTime convertit des bytes DATETIME MySQL en time.Time
func parseMySQLDateTime(b []byte) (time.Time, error) {
	if len(b) == 0 {
		return time.Time{}, nil
	}
	// MySQL renvoie "2006-01-02 15:04:05" ou "2006-01-02 15:04:05.123456"
	s := string(b)
	if len(s) > 19 {
		s = s[:19]
	}
	return time.Parse("2006-01-02 15:04:05", s)
}
