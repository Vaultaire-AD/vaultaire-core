package permission

import (
	"strings"
)

// IsAuthorized vérifie si une liste de permissions autorise un domaine
//
// Un « deny » parmi elles refuse tout, quel que soit l'ordre (TO-DO 104).
func IsUserAuthorizedToSearch(rawPermissions []string, domain string) bool {
	if ContientUnRefus(rawPermissions) {
		return false
	}
	for _, raw := range rawPermissions {
		pa := ParsePermissionAction(raw)

		switch pa.Type {
		case "all":
			return true

		case "custom":
			// Avec propagation
			for _, d := range pa.WithPropagation {
				if domain == d || strings.HasSuffix(domain, "."+d) {
					return true
				}
			}
			// Sans propagation
			for _, d := range pa.WithoutPropagation {
				if domain == d {
					return true
				}
			}
		case "nil":
			continue
		}
	}
	return false
}
