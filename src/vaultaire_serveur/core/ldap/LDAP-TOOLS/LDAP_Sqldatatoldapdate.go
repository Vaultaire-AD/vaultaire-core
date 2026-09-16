package ldaptools

import (
	"fmt"
	"time"
)

func SQLDateToLDAPFormat(sqlDate string) (string, error) {
	// Format SQL sans heure
	parsedTime, err := time.Parse("2006-01-02", sqlDate)
	if err != nil {
		return "", fmt.Errorf("erreur de parsing de la date SQL: %v", err)
	}
	// Retourne en format LDAP GeneralizedTime
	return parsedTime.UTC().Format("20060102150405") + "Z", nil
}
