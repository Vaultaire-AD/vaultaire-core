package dbgpo

import (
	"fmt"
	"strings"
)

// validateRestrictionValue vérifie la forme d'une valeur de restriction.
func validateRestrictionValue(value string, maxLen int) error {
	if value == "" {
		return fmt.Errorf("valeur vide")
	}
	if len(value) > maxLen {
		return fmt.Errorf("valeur trop longue (%d caractères maximum)", maxLen)
	}
	if strings.ContainsAny(value, "\x00\n\r\t") {
		return fmt.Errorf("valeur contenant un caractère de contrôle")
	}
	return nil
}
