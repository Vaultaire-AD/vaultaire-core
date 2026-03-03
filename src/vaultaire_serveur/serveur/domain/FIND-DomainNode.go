package domain

import (
	"vaultaire/serveur/storage"
	"strings"
)

// findDomainNode cherche le noeud correspondant à domainPath (ex: "back.dev.fr.vaultaire")
func findDomainNode(root *storage.DomainNode, domainPath string) *storage.DomainNode {
	parts := strings.Split(domainPath, ".")
	current := root

	// lecture dans le même ordre que buildDomainTree (de droite à gauche)
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		next, exists := current.Children[part]
		if !exists {
			return nil
		}
		current = next
	}

	return current
}
