package domain

import (
	"DUCKY/serveur/storage"
	"strings"
)

func BuildDomainTree(groups []storage.GroupDomain) *storage.DomainNode {
	root := &storage.DomainNode{
		Name:     "root",
		Children: make(map[string]*storage.DomainNode),
	}

	for _, gd := range groups {
		parts := strings.Split(gd.DomainName, ".")
		current := root

		// on remonte pour créer les noeuds
		for i := len(parts) - 1; i >= 0; i-- {
			part := parts[i]
			if _, ok := current.Children[part]; !ok {
				current.Children[part] = &storage.DomainNode{
					Name:     part,
					Children: make(map[string]*storage.DomainNode),
				}
			}
			current = current.Children[part]

			// Au dernier niveau (i == 0), on peut stocker le domaine complet dans le noeud
			if i == 0 {
				current.FullDomain = gd.DomainName
			}
		}

		current.Groups = append(current.Groups, gd.GroupName)
	}

	return root
}
