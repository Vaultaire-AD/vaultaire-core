package tools

import (
	"fmt"
	"time"
)

func StringToDate(birthdateStr string) (string, error) {
	birthdate, err := time.Parse("02/01/2006", birthdateStr)
	if err != nil {
		return "", fmt.Errorf("format attendu jj/mm/aaaa, reçu: %s", birthdateStr)
	}

	// Formatter la date en format MySQL
	birthdateFormatted := birthdate.Format("2006-01-02")

	return birthdateFormatted, nil
}
