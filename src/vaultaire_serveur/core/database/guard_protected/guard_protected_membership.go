package guardprotected

import isprotected "vaultaire/core/database/is_protected"

// GuardProtectedMembership refuse de retirer le compte d'amorçage du groupe
// superadmin. Le retirer ne supprime rien mais lui ôte toutes ses permissions :
// l'effet pratique est identique à une suppression du compte.
func GuardProtectedMembership(username, groupName string) error {
	if isprotected.IsProtectedUser(username) && isprotected.IsProtectedGroup(groupName) {
		return refuseProtected("couple compte/groupe", username+"/"+groupName, "le retrait d'appartenance")
	}
	return nil
}
