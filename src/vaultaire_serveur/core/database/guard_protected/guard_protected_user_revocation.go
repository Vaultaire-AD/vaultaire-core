package guardprotected

import isprotected "vaultaire/core/database/is_protected"

// GuardProtectedUserRevocation refuse la révocation du compte d'amorçage.
//
// Le kill switch est plus expéditif que la suppression : il coupe le compte
// partout, immédiatement, et en mode hard le détruit ainsi que ses comptes
// locaux sur tout le parc. Appliqué à `vaultaire`, il ferait exactement ce que
// ce fichier existe pour empêcher — se retrouver sans aucun chemin d'accès
// garanti à l'annuaire, et cette fois sur toutes les machines à la fois.
//
// Le compte d'amorçage reste par ailleurs le filet de secours quand une
// révocation a été déclenchée par erreur : il doit rester joignable pour la
// lever.
func GuardProtectedUserRevocation(username, mode string) error {
	if isprotected.IsProtectedUser(username) {
		return refuseProtected("compte", username, "la révocation ("+mode+")")
	}
	return nil
}
