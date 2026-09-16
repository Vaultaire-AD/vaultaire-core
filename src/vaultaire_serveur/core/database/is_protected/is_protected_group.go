package isprotected

import (
	"strings"
)

// IsProtectedGroup indique si un nom de groupe est celui du groupe superadmin.
func IsProtectedGroup(groupName string) bool {
	return strings.EqualFold(strings.TrimSpace(groupName), ProtectedGroupName)
}
