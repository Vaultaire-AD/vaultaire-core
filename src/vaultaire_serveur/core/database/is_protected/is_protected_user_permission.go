package isprotected

import (
	"strings"
)

// IsProtectedUserPermission indique si une permission utilisateur est protégée.
func IsProtectedUserPermission(name string) bool {
	return strings.EqualFold(strings.TrimSpace(name), ProtectedUserPermission)
}
