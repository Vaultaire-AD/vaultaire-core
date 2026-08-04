package guardprotected

import (
	"strings"
	isprotected "vaultaire/core/database/is_protected"
)

// GuardProtectedUserRename refuse le renommage du compte d'amorçage.
//
// Le changement de mot de passe reste autorisé, et c'est délibéré : le compte
// est créé avec un mot de passe par défaut connu, interdire sa rotation ferait
// plus de mal que de bien. Seule l'identité (username) est figée, parce que
// c'est elle qui est câblée dans l'authentification serveur et le bind LDAP.
func GuardProtectedUserRename(currentUsername, newUsername string) error {
	if !isprotected.IsProtectedUser(currentUsername) {
		return nil
	}
	if strings.TrimSpace(newUsername) == "" || isprotected.IsProtectedUser(newUsername) {
		return nil
	}
	return refuseProtected("compte", currentUsername, "le renommage")
}
