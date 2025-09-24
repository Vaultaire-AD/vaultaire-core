package permission

import (
	"DUCKY/serveur/storage"
	"strings"
)

// ParsePermissionContent analyse le contenu d'une permission
func ParsePermissionContent(content string) storage.ParsedPermission {
	result := storage.ParsedPermission{}

	// Cas spéciaux
	if content == "nil" {
		result.Deny = true
		return result
	}
	if content == "*" || content == "all" {
		result.All = true
		return result
	}

	// Split sur ":"
	parts := strings.Split(content, ":")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "0(") && strings.HasSuffix(part, ")") {
			// extraire ce qui est entre les parenthèses
			domains := strings.TrimSuffix(strings.TrimPrefix(part, "0("), ")")
			if domains != "" {
				result.NoPropagation = append(result.NoPropagation, strings.Split(domains, ";")...)
			}
		} else if strings.HasPrefix(part, "1(") && strings.HasSuffix(part, ")") {
			domains := strings.TrimSuffix(strings.TrimPrefix(part, "1("), ")")
			if domains != "" {
				result.WithPropagation = append(result.WithPropagation, strings.Split(domains, ";")...)
			}
		}
	}

	return result
}
