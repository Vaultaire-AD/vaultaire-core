package isprotected

import (
	"strings"
)

// IsProtectedClientPermission indique si une permission client est protégée.
func IsProtectedClientPermission(name string) bool {
	return strings.EqualFold(strings.TrimSpace(name), ProtectedClientPermission)
}
