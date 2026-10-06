package domain

import (
	"database/sql"
	"strings"
	dbdomains "vaultaire/core/database/db_domains"
)

// NormaliserDomaine met un nom de domaine sous sa forme de comparaison :
// minuscules, sans espaces de bord ni point final.
//
// EXPORTÉE parce qu'elle décide de ce qui est chargé, et que le contrôle d'accès
// LDAP doit décider de ce qui est RENDU avec exactement la même règle
// (`security.PorteeDeRecherche`, point 120). Deux normalisations qui se
// ressemblent finissent par diverger, et la divergence se manifeste alors en
// entrée chargée puis écartée — ou l'inverse.
func NormaliserDomaine(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ".")
	return strings.ToLower(s)
}

func normalizeDomain(s string) string {
	return NormaliserDomaine(s)
}

// GetGroupsUnderDomain retourne tous les noms de groupes appartenant à un domaine
// et à tous ses sous-domaines (scope subtree LDAP)
// Exemples :
//
//	domainPath = "vaultaire.local"
//	g.DomainName == "vaultaire.local"         -> included
//	g.DomainName == "vpn.vaultaire.local"     -> included
//	g.DomainName == "intra.vpn.vaultaire.local" -> included
func GetGroupsUnderDomain(domainPath string, db *sql.DB, returnDomain bool) ([]string, error) {
	allGroups, err := dbdomains.GetAllGroupsWithDomains(db)
	if err != nil {
		return nil, err
	}

	target := normalizeDomain(domainPath)
	seen := make(map[string]struct{})
	result := []string{}

	// Quand on demande les domaines (et non les noms de groupes), on inclut toujours
	// le domaine de base de recherche pour conserver un point d'ancrage LDAP stable.
	// Exemple: baseDN=enov.local doit rester présent même si seuls des groupes
	// existent dans admin.enov.local.
	if returnDomain && target != "" {
		seen[target] = struct{}{}
		result = append(result, target)
	}

	for _, g := range allGroups {
		if g.DomainName == "" || g.GroupName == "" {
			continue
		}
		dn := normalizeDomain(g.DomainName)
		if dn == target || strings.HasSuffix(dn, "."+target) {
			var val string
			var key string
			if returnDomain {
				// On renvoie un domaine normalisé pour éviter les doublons de casse.
				val = dn
				key = dn
			} else {
				val = g.GroupName
				key = val
			}
			if _, ok := seen[key]; !ok {
				seen[key] = struct{}{}
				result = append(result, val)
			}
		}
	}

	return result, nil
}

// GetGroupsDirectlyUnderDomain retourne uniquement les groupes appartenant au domaine
// exact ou à ses sous-domaines immédiats (scope LDAP 1 ou "onelevel")
// Exemples :
//
//	domainPath = "vaultaire.local"
//	g.DomainName == "vaultaire.local"         -> included
//	g.DomainName == "vpn.vaultaire.local"     -> included (immediate child)
//	g.DomainName == "intra.vpn.vaultaire.local" -> NOT included
func GetGroupsDirectlyUnderDomain(domainPath string, db *sql.DB, returnDomain bool) ([]string, error) {
	allGroups, err := dbdomains.GetAllGroupsWithDomains(db)
	if err != nil {
		return nil, err
	}
	target := normalizeDomain(domainPath)
	seen := make(map[string]struct{})
	result := []string{}

	for _, g := range allGroups {

		if g.DomainName == "" || g.GroupName == "" {
			continue
		}
		dn := normalizeDomain(g.DomainName)

		// Domaine exact
		if dn == target {
			var val string
			if returnDomain {
				val = g.DomainName
			} else {
				val = g.GroupName
			}
			if _, ok := seen[val]; !ok {
				seen[val] = struct{}{}
				result = append(result, val)
			}
			continue
		}

		// Sous-domaine immédiat
		suffix := "." + target
		if strings.HasSuffix(dn, suffix) {
			extra := strings.TrimSuffix(dn, suffix)
			if extra != "" && !strings.Contains(extra, ".") { // sous-domaine immédiat
				var val string
				if returnDomain {
					val = g.DomainName
				} else {
					val = g.GroupName
				}
				if _, ok := seen[val]; !ok {
					seen[val] = struct{}{}
					result = append(result, val)
				}
			}
		}
	}

	return result, nil
}

// GetGroupsDirectlyUnderDomainExact retourne uniquement les groupes appartenant exactement
// au domaine donné, sans inclure les sous-domaines.
// Exemples :
//
//	domainPath = "vaultaire.local"
//	g.DomainName == "vaultaire.local" -> included
//	g.DomainName == "vpn.vaultaire.local" -> NOT included
func GetGroupsDirectlyUnderDomainExact(domainPath string, db *sql.DB, returnDomain bool) ([]string, error) {
	allGroups, err := dbdomains.GetAllGroupsWithDomains(db)
	if err != nil {
		return nil, err
	}

	target := normalizeDomain(domainPath)
	result := []string{}

	// Sans écriture sur la sortie standard (TO-DO 145). Un `fmt.Printf` de mise
	// au point était resté ici : une ligne « DEBUG: checking… » par groupe de
	// l'annuaire, à CHAQUE recherche LDAP de portée `one`, mode debug actif ou
	// non — hors du journal, donc sans horodatage, sans niveau et sans moyen de
	// l'éteindre.
	for _, g := range allGroups {
		if g.DomainName == "" || g.GroupName == "" {
			continue
		}
		if normalizeDomain(g.DomainName) == target {
			if returnDomain {
				result = append(result, g.DomainName)
			} else {
				result = append(result, g.GroupName)
			}
		}
	}

	return result, nil
}

// GetAllGroupDomains retourne la liste de tous les DomainName existants dans la base (sans doublons)
func GetAllGroupDomains(db *sql.DB, returnDomain bool) ([]string, error) {
	allGroups, err := dbdomains.GetAllGroupsWithDomains(db)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	result := []string{}

	for _, g := range allGroups {
		var val string
		if returnDomain {
			if g.DomainName == "" {
				continue
			}
			val = normalizeDomain(g.DomainName)
		} else {
			if g.GroupName == "" {
				continue
			}
			val = g.GroupName
		}

		if _, ok := seen[val]; !ok {
			seen[val] = struct{}{}
			result = append(result, val)
		}
	}

	return result, nil
}
