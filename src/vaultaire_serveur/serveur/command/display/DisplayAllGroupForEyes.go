package display

import (
	"DUCKY/serveur/storage" // adapte selon ton package
	"fmt"
	"sort"
	"strings"
)

// PrintDomainTreeRoot affiche tous les domaines racines contenus dans root.
func PrintDomainTreeRoot(root *storage.DomainNode) string {
	var sb strings.Builder

	// Ordonner les domaines racines pour stabilité de l'affichage
	keys := make([]string, 0, len(root.Children))
	for k := range root.Children {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for i, key := range keys {
		child := root.Children[key]
		isLast := i == len(keys)-1

		sb.WriteString(printDomainNode(child, "", isLast, child.Name))
	}

	return sb.String()
}

// printDomainNode affiche un nœud avec indentation et symboles graphiques.
// prefixIndent : indentation accumulée pour le niveau courant (ex: "│   ")
// isLast : indique si ce nœud est le dernier frère (pour le └──)
// fullDomain : nom complet du domaine jusqu’ici (ex: "admin.fr.vaultaire")
func printDomainNode(node *storage.DomainNode, prefixIndent string, isLast bool, fullDomain string) string {
	var sb strings.Builder

	// Affiche la ligne avec ├── ou └── et nom du domaine
	branch := "├── "
	nextPrefix := prefixIndent + "│   "
	if isLast {
		branch = "└── "
		nextPrefix = prefixIndent + "    "
	}

	sb.WriteString(prefixIndent)
	sb.WriteString(branch)
	sb.WriteString(node.Name)
	sb.WriteString("\n")

	// Trie les groupes pour ordre stable
	sort.Strings(node.Groups)
	for i, group := range node.Groups {
		groupIsLast := (i == len(node.Groups)-1 && len(node.Children) == 0)
		groupBranch := "├── "
		// groupIndent := nextPrefix + "    "
		if groupIsLast {
			groupBranch = "└── "
		}
		// Affiche le groupe avec full domain complet
		sb.WriteString(nextPrefix)
		sb.WriteString(groupBranch)
		sb.WriteString(fmt.Sprintf("* Group: %s (%s)\n", group, fullDomain))
	}

	// Trie enfants par nom pour ordre stable
	keys := make([]string, 0, len(node.Children))
	for k := range node.Children {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for i, k := range keys {
		child := node.Children[k]
		childIsLast := i == len(keys)-1

		// Construit le fullDomain pour l'enfant (ex: enfant.nodeName + "." + fullDomain)
		childFullDomain := child.Name + "." + fullDomain

		sb.WriteString(printDomainNode(child, nextPrefix, childIsLast, childFullDomain))
	}

	return sb.String()
}
