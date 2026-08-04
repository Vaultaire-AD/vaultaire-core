package dbdomains

import (
	"errors"
	"strings"
)

// Récupérer le domaine principal, ex: company.com à partir de finance.company.com
func ExtractMainDomain(domain string) (string, error) {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return "", errors.New("domaine invalide")
	}
	n := len(parts)
	return parts[n-2] + "." + parts[n-1], nil
}
