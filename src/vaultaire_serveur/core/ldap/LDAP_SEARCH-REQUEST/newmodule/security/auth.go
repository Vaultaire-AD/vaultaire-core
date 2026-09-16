package security

import (
	"strings"
	"vaultaire/core/database"
	dbpermission "vaultaire/core/database/db_permission"
	"vaultaire/core/permission"
)

func IsAuthorizedToSearch(username, baseDN string) bool {
	// Nom vide : refus immédiat.
	//
	// C'est la valeur que porte une session anonyme. Interroger le RBAC avec elle
	// ne rendrait probablement rien, mais « probablement » n'est pas une garantie :
	// il suffirait d'une jointure permissive pour que l'anonyme hérite de droits.
	//
	// Le dispatcheur interdit déjà à un anonyme toute recherche autre que RootDSE.
	// Ce contrôle-ci est le second verrou, local à la décision.
	if strings.TrimSpace(username) == "" {
		return false
	}

	perms, err := dbpermission.GetUserPermissionsForAction(
		database.GetDatabase(),
		username,
		"search",
	)
	if err != nil {
		return false
	}
	return permission.IsUserAuthorizedToSearch(perms, baseDN)
}
