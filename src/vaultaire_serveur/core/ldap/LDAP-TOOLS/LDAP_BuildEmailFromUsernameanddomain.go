package ldaptools

import (
	"strings"
)

func BuildEmailFromUsernameAndDomain(username, fullDomain string) string {
	parts := strings.Split(fullDomain, ".")
	if len(parts) < 2 {
		return username + "@invalid-domain"
	}
	domainSource := strings.Join(parts[len(parts)-2:], ".") // ex: company.com
	return username + "@" + domainSource
}
