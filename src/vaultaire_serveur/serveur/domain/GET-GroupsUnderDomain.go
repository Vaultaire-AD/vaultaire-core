package domain

import (
	"DUCKY/serveur/database"
	"database/sql"
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
