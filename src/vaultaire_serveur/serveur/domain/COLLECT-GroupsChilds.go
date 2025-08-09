package domain

import "DUCKY/serveur/storage"

func collectGroupsChilds(node *storage.DomainNode, groups *[]string) {
	*groups = append(*groups, node.Groups...)

	for _, child := range node.Children {
		collectGroupsChilds(child, groups)
	}
}
