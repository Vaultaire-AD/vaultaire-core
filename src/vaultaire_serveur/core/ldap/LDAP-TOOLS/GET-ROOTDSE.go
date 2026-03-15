package ldaptools

import (
	"strings"
	"vaultaire/core/database"
	"vaultaire/core/domain"
)

func GetDefaultRootDN() []string {
	domains, err := domain.GetAllGroupDomains(database.GetDatabase(), true)
	if err != nil {
		return []string{"dc=default,dc=local"}
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
