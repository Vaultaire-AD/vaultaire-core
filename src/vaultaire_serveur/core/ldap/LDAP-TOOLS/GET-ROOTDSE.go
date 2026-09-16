package ldaptools

import (
	"strings"
	"vaultaire/core/database"
	"vaultaire/core/domain"
)

// DefaultRootDN est la racine annoncée quand l'annuaire n'est pas lisible.
//
// Une valeur de repli plutôt qu'une erreur : le RootDSE est la seule chose
// qu'un client obtient AVANT de s'authentifier, et un client qui n'obtient
// pas de RootDSE ne sait même pas quoi tenter ensuite.
const DefaultRootDN = "dc=default,dc=local"

func GetDefaultRootDN() []string {
	// La base peut être NIL, et pas seulement injoignable.
	//
	// database/sql ne rend pas d'erreur dans ce cas : il DÉRÉFÉRENCE un
	// pointeur nil et panique. Or ce chemin est atteint par une requête
	// RootDSE, c'est-à-dire par un inconnu, avant toute authentification.
	//
	// En exploitation normale la base est initialisée avant que le port LDAP
	// n'écoute. Mais « normalement » ne suffit pas pour un chemin exposé et
	// non authentifié : un ordre de démarrage modifié, une réinitialisation
	// de connexion, et le serveur entier s'arrête sur une requête de
	// découverte.
	db := database.GetDatabase()
	if db == nil {
		return []string{DefaultRootDN}
	}

	domains, err := domain.GetAllGroupDomains(db, true)
	if err != nil {
		return []string{DefaultRootDN}
	}

	var rootDNs []string
	// On veut extraire les racines uniques, ex: vaultaire.fr et vaultaire.local
	// même si on a sous.administration.vaultaire.local
	seen := make(map[string]bool)

	for _, d := range domains {
		parts := strings.Split(d, ".")
		if len(parts) < 2 {
			continue
		}

		// On prend les deux derniers composants (ex: vaultaire.fr)
		rootDomain := parts[len(parts)-2] + "." + parts[len(parts)-1]

		if !seen[rootDomain] {
			// Transformation en format DC
			var dcParts []string
			for _, p := range strings.Split(rootDomain, ".") {
				dcParts = append(dcParts, "dc="+p)
			}
			rootDNs = append(rootDNs, strings.Join(dcParts, ","))
			seen[rootDomain] = true
		}
	}
	return rootDNs
}
