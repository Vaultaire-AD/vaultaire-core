package guardprotected

import isprotected "vaultaire/core/database/is_protected"

// GuardProtectedUserDeletion refuse la suppression du compte d'amorçage.
func GuardProtectedUserDeletion(username string) error {
	if isprotected.IsProtectedUser(username) {
		return refuseProtected("compte", username, "la suppression")
	}
	return nil
}
