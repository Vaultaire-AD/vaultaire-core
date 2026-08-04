package dbgpo

import (
	"strings"
)

// nullIfEmpty convertit une chaîne vide en NULL SQL, pour distinguer « pas de
// note » d'une note vide.
func nullIfEmpty(s string) interface{} {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}
