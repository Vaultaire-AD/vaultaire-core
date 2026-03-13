package ldaptools

import "strings"

// Utilitaire pour convertir "administration.vaultaire.local" → "dc=administration,dc=vaultaire,dc=local"
func DomainToDC(domain string) string {
	parts := strings.Split(domain, ".")
	dcParts := make([]string, len(parts))
	for i, p := range parts {
		dcParts[i] = "dc=" + p
	}
	return strings.Join(dcParts, ",")
}

// Utilitaire pour convertir "administration.vaultaire.local" → "dc=administration,dc=vaultaire,dc=local"
func DomainToDN(domain string) string {
	parts := strings.Split(domain, ".")
	dc := make([]string, 0, len(parts))
	for _, p := range parts {
		dc = append(dc, "dc="+p)
	}
	return strings.Join(dc, ",")
}
