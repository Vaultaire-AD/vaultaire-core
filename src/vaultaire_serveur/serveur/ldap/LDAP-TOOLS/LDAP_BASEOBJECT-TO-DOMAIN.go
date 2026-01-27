package ldaptools

import "strings"

// ConvertLDAPBaseToDomainName extrait le domaine à partir d'un BaseObject LDAP
func ConvertLDAPBaseToDomainName(base string) string {
	parts := strings.Split(base, ",")
	var domainParts []string

	// On parcourt les parties de droite à gauche pour reconstruire le domaine
	for i := len(parts) - 1; i >= 0; i-- {
		part := strings.TrimSpace(parts[i])
		if strings.HasPrefix(strings.ToLower(part), "dc=") {
			domainParts = append([]string{strings.TrimPrefix(part, "dc=")}, domainParts...)
		}
	}

	return strings.Join(domainParts, ".")
}
