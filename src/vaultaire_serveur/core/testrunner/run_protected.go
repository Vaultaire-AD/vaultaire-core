package testrunner

import (
	guardprotected "vaultaire/core/database/guard_protected"
	isprotected "vaultaire/core/database/is_protected"
)

// Tests d'immuabilité de l'identité d'amorçage.
//
// Ces garde-fous portent sur des fonctions pures (pas d'accès base), donc ils
// sont vérifiables sans connexion. Ce qu'on teste ici n'est pas « la suppression
// marche » mais « la suppression est refusée », et surtout qu'elle est refusée
// pour toutes les variantes de casse — un contournement par « Vaultaire » serait
// une régression silencieuse.
func testProtectedIdentity() []Result {
	var out []Result

	// Reconnaissance insensible à la casse.
	caseOK := isprotected.IsProtectedUser("vaultaire") &&
		isprotected.IsProtectedUser("Vaultaire") &&
		isprotected.IsProtectedUser("VAULTAIRE") &&
		isprotected.IsProtectedUser("  vaultaire  ") &&
		isprotected.IsProtectedGroup("VaUlTaIrE")
	out = append(out, Result{"Protection: reconnaissance insensible à la casse", caseOK,
		"une variante de casse échappe à la protection"})

	// Un nom voisin ne doit pas être protégé par erreur.
	notProtected := !isprotected.IsProtectedUser("vaultaire2") &&
		!isprotected.IsProtectedUser("vault") &&
		!isprotected.IsProtectedGroup("vaultaire-admins")
	out = append(out, Result{"Protection: pas de faux positif sur les noms voisins", notProtected,
		"un nom distinct est protégé à tort"})

	// Suppressions refusées.
	out = append(out, Result{"Protection: suppression du compte refusée",
		guardprotected.GuardProtectedUserDeletion("vaultaire") != nil, "devrait refuser"})
	out = append(out, Result{"Protection: suppression du groupe refusée",
		guardprotected.GuardProtectedGroupDeletion("vaultaire") != nil, "devrait refuser"})
	out = append(out, Result{"Protection: suppression de la permission complète refusée",
		guardprotected.GuardProtectedUserPermissionDeletion("vaultaire_all") != nil, "devrait refuser"})
	out = append(out, Result{"Protection: suppression de la permission client admin refusée",
		guardprotected.GuardProtectedClientPermissionDeletion("vaultaire_admin") != nil, "devrait refuser"})

	// Renommages refusés.
	out = append(out, Result{"Protection: renommage du compte refusé",
		guardprotected.GuardProtectedUserRename("vaultaire", "root") != nil, "devrait refuser"})
	out = append(out, Result{"Protection: renommage du groupe refusé",
		guardprotected.GuardProtectedGroupRename("vaultaire", "admins") != nil, "devrait refuser"})

	// Un renommage vers le même nom, ou sans nouveau nom, n'est pas un renommage :
	// c'est le cas d'une simple mise à jour de profil ou de mot de passe, qui doit
	// rester possible pour permettre la rotation du mot de passe par défaut.
	renameNoop := guardprotected.GuardProtectedUserRename("vaultaire", "vaultaire") == nil &&
		guardprotected.GuardProtectedUserRename("vaultaire", "") == nil
	out = append(out, Result{"Protection: mise à jour sans renommage autorisée", renameNoop,
		"la rotation du mot de passe du compte d'amorçage est bloquée à tort"})

	// Le retrait d'appartenance et le détachement de permission sont refusés.
	out = append(out, Result{"Protection: retrait du compte de son groupe refusé",
		guardprotected.GuardProtectedMembership("vaultaire", "vaultaire") != nil, "devrait refuser"})
	out = append(out, Result{"Protection: détachement de la permission du groupe refusé",
		guardprotected.GuardProtectedUserPermissionUnlink("vaultaire", "vaultaire_all") != nil, "devrait refuser"})

	// Les mêmes opérations sur d'autres objets doivent rester autorisées.
	othersAllowed := guardprotected.GuardProtectedUserDeletion("alice") == nil &&
		guardprotected.GuardProtectedGroupDeletion("dev") == nil &&
		guardprotected.GuardProtectedMembership("alice", "vaultaire") == nil &&
		guardprotected.GuardProtectedUserPermissionUnlink("dev", "vaultaire_all") == nil
	out = append(out, Result{"Protection: opérations normales non entravées", othersAllowed,
		"une opération légitime est bloquée"})

	return out
}
