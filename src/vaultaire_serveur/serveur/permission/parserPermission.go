package permission

import (
	"vaultaire/serveur/storage"
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

	// Nettoyer les parenthèses extérieures et splitter sur ")("
	content = strings.TrimSpace(content)
	blocks := strings.Split(content, ")(")
	for i, b := range blocks {
		b = strings.TrimPrefix(b, "(")
		b = strings.TrimSuffix(b, ")")
		blocks[i] = b
	}

	for _, b := range blocks {
		if len(b) < 2 {
			continue
		}
		switch b[:1] {
		case "0":
			if len(b) > 2 && b[1] == ':' {
				result.NoPropagation = append(result.NoPropagation, strings.Split(b[2:], ",")...)
			}
		case "1":
			if len(b) > 2 && b[1] == ':' {
				result.WithPropagation = append(result.WithPropagation, strings.Split(b[2:], ",")...)
			}
		}
	}

	// Nettoyage des espaces
	for i, d := range result.WithPropagation {
		result.WithPropagation[i] = strings.TrimSpace(d)
	}
	for i, d := range result.NoPropagation {
		result.NoPropagation[i] = strings.TrimSpace(d)
	}

	return result
}
