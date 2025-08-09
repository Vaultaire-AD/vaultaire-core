package ldaptools

import "strings"

func ConvertLDAPBaseToDomainName(base string) string {
	parts := strings.Split(base, ",")
	var domainParts []string

	for _, part := range parts {
		if strings.HasPrefix(part, "dc=") {
			domainParts = append(domainParts, strings.TrimPrefix(part, "dc="))
		}
	}

	return strings.Join(domainParts, ".")
}
