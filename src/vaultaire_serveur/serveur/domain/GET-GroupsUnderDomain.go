package domain

import (
	"DUCKY/serveur/database"
	"database/sql"
	"strings"
)

// GetGroupsUnderDomain retourne tous les groupes appartenant à un domaine et ses sous-domaines
func GetGroupsUnderDomain(domainPath string, db *sql.DB) ([]string, error) {
	allGroups, err := database.GetAllGroupsWithDomains(db)
	if err != nil {
		return nil, err
	}

	tree := BuildDomainTree(allGroups)

	targetNode := findDomainNode(tree, domainPath)
	if targetNode == nil {
		return nil, nil // domaine non trouvé
	}

	var result []string
	collectGroupsChilds(targetNode, &result)
	return result, nil
}

// GetDirectGroupsUnderDomain retourne uniquement les groupes appartenant directement au domaine (non récursif)
// GetDirectGroupsUnderDomain retourne uniquement les groupes appartenant
// directement au domaine (non récursif) ou aux sous-domaines immédiats.
// Exemples:
//
//	domainPath = "vaultaire.local"
//	g.DomainName == "vaultaire.local"         -> included
//	g.DomainName == "vpn.vaultaire.local"     -> included (immediate child)
//	g.DomainName == "intra.vpn.vaultaire.local" -> NOT included (grand-child)
func GetDirectGroupsDomainUnderDomain(domainPath string, db *sql.DB) ([]string, error) {
	allGroups, err := database.GetAllGroupsWithDomains(db)
	if err != nil {
		return nil, err
	}

	// Normalisation : lowercase et suppression d'un point final éventuel
	normalize := func(s string) string {
		s = strings.TrimSpace(s)
		s = strings.TrimSuffix(s, ".")
		return strings.ToLower(s)
	}
	target := normalize(domainPath)

	var directGroups []string
	for _, g := range allGroups {
		if g.DomainName == "" {
			continue
		}
		dn := normalize(g.DomainName)

		// cas 1 : domaine identique
		if dn == target {
			directGroups = append(directGroups, g.GroupName)
			continue
		}

		// cas 2 : sous-domaine ; vérifier suffixe ".<target>"
		suffix := "." + target
		if strings.HasSuffix(dn, suffix) {
			// extra = la partie avant ".<target>"
			extra := strings.TrimSuffix(dn, suffix) // ex: "vpn"  ou "intra.vpn"
			// On veut accepter seulement les sous-domaines *immédiats* :
			// donc extra ne doit pas contenir de '.' (un seul label)
			if extra != "" && !strings.Contains(extra, ".") {
				directGroups = append(directGroups, g.DomainName)
			}
		}
	}

	return directGroups, nil
}

// GetAllGroupsDomainsUnderDomain retourne tous les DomainName des groupes
// qui appartiennent au domaine donné ou à ses sous-domaines (récursif)
func GetAllGroupsDomainsUnderDomain(domainPath string, db *sql.DB) ([]string, error) {
	allGroups, err := database.GetAllGroupsWithDomains(db)
	if err != nil {
		return nil, err
	}

	normalize := func(s string) string {
		s = strings.TrimSpace(s)
		s = strings.TrimSuffix(s, ".")
		return strings.ToLower(s)
	}
	target := normalize(domainPath)

	seen := make(map[string]struct{})
	for _, g := range allGroups {
		if g.DomainName == "" {
			continue
		}
		dn := normalize(g.DomainName)

		// On accepte tout domaine qui est exactement le target ou qui finit par ".<target>"
		if dn == target || strings.HasSuffix(dn, "."+target) {
			seen[g.DomainName] = struct{}{}
		}
	}

	// construire le slice sans doublons
	result := make([]string, 0, len(seen))
	for d := range seen {
		result = append(result, d)
	}

	return result, nil
}
