package display

import (
	"sort"
	"strings"

	"vaultaire/core/storage"
)

// Arborescence des domaines et de leurs groupes.
//
// Seul affichage du CLI qui ne soit ni une table ni une fiche : la hiérarchie
// des domaines est l'information, et l'aplatir en colonnes la perdrait. Les
// glyphes de branche portent donc l'alignement, et le module table.go n'est
// pas employé ici.

// PrintDomainTreeRoot affiche tous les domaines racines contenus dans root.
func PrintDomainTreeRoot(root *storage.DomainNode) string {
	// Garde sur nil : la fonction déréférence root.Children à la ligne
	// suivante. Un affichage est le dernier endroit où l'absence de données
	// doit arrêter le programme — et un appelant qui n'a trouvé aucun domaine
	// peut légitimement passer nil.
	if root == nil || len(root.Children) == 0 {
		return "Aucun domaine.\n"
	}

	var sb strings.Builder
	for i, key := range clesTriees(root.Children) {
		enfant := root.Children[key]
		sb.WriteString(noeudDomaine(enfant, "", i == len(root.Children)-1, enfant.Name))
	}
	return sb.String()
}

// clesTriees rend les noms des enfants dans un ordre stable.
//
// Le parcours d'une map Go est volontairement aléatoire : sans tri, deux
// affichages successifs de la même arborescence sortent dans un ordre
// différent, ce qui se lit comme un changement de la structure.
func clesTriees(enfants map[string]*storage.DomainNode) []string {
	cles := make([]string, 0, len(enfants))
	for k := range enfants {
		cles = append(cles, k)
	}
	sort.Strings(cles)
	return cles
}

// noeudDomaine affiche un nœud, ses groupes, puis ses sous-domaines.
//
// prefixe    : indentation héritée des niveaux supérieurs (« │   » ou «     »)
// dernier    : ce nœud est-il le dernier de sa fratrie (└── au lieu de ├──)
// domaineFQ  : nom complet du domaine à ce niveau (ex. « admin.fr.vaultaire »)
func noeudDomaine(node *storage.DomainNode, prefixe string, dernier bool, domaineFQ string) string {
	if node == nil {
		return ""
	}

	branche, prefixeEnfants := "├── ", prefixe+"│   "
	if dernier {
		branche, prefixeEnfants = "└── ", prefixe+"    "
	}

	var sb strings.Builder
	sb.WriteString(prefixe + branche + node.Name + "\n")

	// Copie avant tri.
	//
	// L'ancienne version appelait sort.Strings(node.Groups), ce qui réordonne
	// la tranche DE L'APPELANT : une fonction d'affichage modifiait la
	// structure qu'on lui donnait à lire. Inoffensif tant que personne ne
	// dépend de l'ordre d'origine, et impossible à retrouver le jour où
	// quelqu'un en dépend.
	groupes := make([]string, len(node.Groups))
	copy(groupes, node.Groups)
	sort.Strings(groupes)

	cles := clesTriees(node.Children)

	for i, g := range groupes {
		// Un groupe n'est le dernier trait de ce niveau que s'il ne reste ni
		// groupe ni sous-domaine après lui.
		brancheGroupe := "├── "
		if i == len(groupes)-1 && len(cles) == 0 {
			brancheGroupe = "└── "
		}
		// Le domaine complet est répété sur chaque groupe : l'arborescence le
		// donne par position, mais le lire impose de remonter les niveaux —
		// alors qu'il faut le saisir tel quel dans les commandes (-d).
		sb.WriteString(prefixeEnfants + brancheGroupe + "groupe " + g +
			"  (" + domaineFQ + ")\n")
	}

	for i, k := range cles {
		enfant := node.Children[k]
		sb.WriteString(noeudDomaine(
			enfant,
			prefixeEnfants,
			i == len(cles)-1,
			enfant.Name+"."+domaineFQ,
		))
	}

	return sb.String()
}
