package isprotected

import (
	"database/sql"
	"vaultaire/core/database"
)

// IsSuperadmin indique si l'utilisateur est membre du groupe superadmin.
//
// L'appartenance est relue en base à chaque vérification, jamais mise en cache,
// pour qu'un retrait du groupe prenne effet immédiatement. IsUserInGroup vit
// dans groups.go : c'est une lecture d'appartenance ordinaire, pas une garde.
func IsSuperadmin(db *sql.DB, username string) bool {
	member, err := database.IsUserInGroup(db, username, ProtectedGroupName)
	if err != nil {
		// En cas d'erreur de lecture on refuse : une panne de base ne doit pas
		// ouvrir l'accès aux réglages les plus sensibles du produit.
		return false
	}
	return member
}
