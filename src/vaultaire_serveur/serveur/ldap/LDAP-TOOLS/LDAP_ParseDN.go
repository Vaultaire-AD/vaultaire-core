package ldaptools

import (
	"strings"
)

func ExtractUsernameAndDomain(ldapName string) (username, domain, ou string) {
	// Cas simple : pas de DN, juste un nom d’utilisateur
	if !strings.Contains(ldapName, "=") {
		return ldapName, "", ""
	}

	// On parse les parties (séparées par ,)
	parts := strings.Split(ldapName, ",")

	var cn string
	var dcParts []string

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "uid=") {
			cn = strings.TrimPrefix(part, "uid=")
		} else if strings.HasPrefix(part, "cn=") {
			cn = strings.TrimPrefix(part, "cn=")
		} else if strings.HasPrefix(part, "dc=") {
			dcParts = append(dcParts, strings.TrimPrefix(part, "dc="))
		} else if strings.HasPrefix(part, "ou=") {
			ou = strings.TrimPrefix(part, "ou=")
		}
	}

	domain = strings.Join(dcParts, ".")

	return cn, domain, ou
}
