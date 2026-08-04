package dbgroups

import (
	"strings"
)

// Fonction utilitaire pour split + trim chaque élément
func splitTrim(s, sep string) []string {
	parts := []string{}
	for _, part := range strings.Split(s, sep) {
		parts = append(parts, strings.TrimSpace(part))
	}
	return parts
}
