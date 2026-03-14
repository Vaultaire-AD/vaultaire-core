package domain

import "vaultaire/core/storage"

func collectGroupsChilds(node *storage.DomainNode, groups *[]string) {
	*groups = append(*groups, node.Groups...)

	for _, child := range node.Children {
		collectGroupsChilds(child, groups)
	}
}
