package permission

import (
	"vaultaire/serveur/storage"
	"strings"
)

// ConvertPermissionActionToString transforme une PermissionAction en string DB
func ConvertPermissionActionToString(pa storage.PermissionAction) string {
	switch pa.Type {
	case "nil":
		return "nil"
	case "all":
		return "all"
	case "custom":
		var parts []string
		if len(pa.WithPropagation) > 0 {
			domains := strings.Join(pa.WithPropagation, ",")
			parts = append(parts, "(1:"+domains+")")
		}
		if len(pa.WithoutPropagation) > 0 {
			domains := strings.Join(pa.WithoutPropagation, ",")
			parts = append(parts, "(0:"+domains+")")
		}
		return strings.Join(parts, "")
	default:
		return "nil"
	}
}
