package ldaptools

import "strings"

// ToDN convertit "admin.vaultaire.local" -> "dc=admin,dc=vaultaire,dc=local"
func ToDN(domain string) string {
	parts := strings.Split(strings.ToLower(domain), ".")
	for i, p := range parts {
		parts[i] = "dc=" + p
	}
	return strings.Join(parts, ",")
}

// ToRootDN convertit "admin.vaultaire.local" -> "dc=vaultaire,dc=local"
// Elle prend les deux derniers segments du domaine.
func ToRootDN(domain string) string {
	parts := strings.Split(strings.ToLower(domain), ".")
	if len(parts) > 2 {
		// On ne garde que les 2 derniers (ex: "vaultaire", "local")
		parts = parts[len(parts)-2:]
	}
	for i, p := range parts {
		parts[i] = "dc=" + p
	}
	return strings.Join(parts, ",")
}
