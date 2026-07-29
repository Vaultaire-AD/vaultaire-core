package permission

import (
	"vaultaire/core/domain"
)

// CanUserConnectToDomain vérifie si un login au format "user@domain" (ou
// juste "user", sans domaine) a le droit de se connecter sous ce domaine.
//
// Ça répond à "est-ce que ce user appartient à un groupe (ou sous-groupe,
// via les règles de propagation) autorisé sur ce domaine ?" en réutilisant
// exactement le même mécanisme que le bind LDAP (LDAP_bind.go) : action
// legacy "auth", résolue via PrePermissionCheck puis vérifiée par
// CheckPermissionsMultipleDomains, qui gère déjà All / WithPropagation /
// NoPropagation / Deny.
//
// Exemple : CanUserConnectToDomain("test@test.domain.com") vérifie que
// "test" a le droit "auth" sur "test.domain.com", ou sur un domaine parent
// qui propage vers lui (ex "domain.com" avec propagation).
//
// Si le login ne contient pas de domaine (pas de "@"), seul un accès super
// admin (All, tous domaines) peut autoriser la connexion — comportement
// hérité de CheckPermissionsMultipleDomains quand la liste de domaines à
// vérifier est vide.
//
// Retourne (false, raison) si l'utilisateur n'existe pas, si l'action "auth"
// est invalide (ne devrait pas arriver, elle est légale par défaut), ou si
// aucune règle n'autorise l'accès à ce domaine.
func CanUserConnectToDomain(login string) (bool, string) {
	username, targetDomain := domain.ExctractDomainFromUsername(login)

	groupIDs, action, err := PrePermissionCheck(username, "auth")
	if err != nil {
		return false, err.Error()
	}

	var domainsToCheck []string
	if targetDomain != "" {
		domainsToCheck = []string{targetDomain}
	}

	return CheckPermissionsMultipleDomains(groupIDs, action, domainsToCheck)
}
