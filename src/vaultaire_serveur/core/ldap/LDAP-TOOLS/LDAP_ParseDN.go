package ldaptools

import (
	"strings"
)

// ExtractUsernameAndDomain analyse un nom LDAP ou UPN et renvoie le username, le domaine et éventuellement l'OU.
// Exemples acceptés :
//   - "uid=jdupont,ou=IT,dc=example,dc=com"
//   - "cn=Admin,dc=ynov,dc=local"
//   - "jdupont@ldap.domain.com"
//   - "jdupont"
func ExtractUsernameAndDomain(ldapName string) (username, domain, ou string) {
	ldapName = strings.TrimSpace(ldapName)

	// 🔹 Cas 1 : format username@domain
	if strings.Contains(ldapName, "@") && !strings.Contains(ldapName, "=") {
		parts := strings.SplitN(ldapName, "@", 2)
		username = parts[0]
		domain = parts[1]
		return username, domain, ""
	}

	// 🔹 Cas 2 : pas de DN, juste un nom d’utilisateur simple
	if !strings.Contains(ldapName, "=") {
		return ldapName, "", ""
	}

	// 🔹 Cas 3 : format LDAP DN (uid=...,ou=...,dc=...)
	parts := strings.Split(ldapName, ",")

	var cn string
	var dcParts []string

	for _, part := range parts {
		part = strings.TrimSpace(part)
		partLower := strings.ToLower(part)

		if strings.HasPrefix(partLower, "uid=") {
			cn = strings.TrimPrefix(part, "uid=")
		} else if strings.HasPrefix(partLower, "cn=") {
			cn = strings.TrimPrefix(part, "cn=")
		} else if strings.HasPrefix(partLower, "ou=") {
			ou = strings.TrimPrefix(part, "ou=")
		} else if strings.HasPrefix(partLower, "dc=") {
			dcParts = append(dcParts, strings.TrimPrefix(part, "dc="))
		}
	}

	domain = strings.Join(dcParts, ".")
	return cn, domain, ou
}
