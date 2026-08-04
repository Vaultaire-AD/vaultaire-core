package isprotected

import (
	"strings"
)

// IsProtectedUser indique si un nom d'utilisateur est celui du compte d'amorçage.
// La comparaison est insensible à la casse : « Vaultaire » ne doit pas passer.
func IsProtectedUser(username string) bool {
	return strings.EqualFold(strings.TrimSpace(username), ProtectedUsername)
}
