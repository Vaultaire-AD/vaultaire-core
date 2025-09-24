package commandeyes

import (
	"DUCKY/serveur/command/display"
	"DUCKY/serveur/database"
	"DUCKY/serveur/domain"
	"DUCKY/serveur/logs"
)

// parseDomain découpe un nom de domaine en racine et chemin hiérarchique
// func parseDomain(domain string) (domainRoot string, subTree []string) {
// 	parts := strings.Split(domain, ".")
// 	if len(parts) < 2 {
// 		return domain, []string{}
// 	}

// 	domainRoot = parts[len(parts)-2] + "." + parts[len(parts)-1]
// 	subTree = parts[:len(parts)-2]

// 	// Inverser pour avoir l’ordre logique
// 	for i, j := 0, len(subTree)-1; i < j; i, j = i+1, j-1 {
// 		subTree[i], subTree[j] = subTree[j], subTree[i]
// 	}

// 	return domainRoot, subTree
// }

// eyes_by_domain affiche les informations des groupes et de leurs domaines
// pour la commande "eyes -d".
// Elle construit un arbre de domaines et affiche les informations de manière structurée.
// Elle retourne une chaîne de caractères contenant les informations formatées.
// Si une erreur survient lors de la récupération des groupes, elle retourne un message d'erreur.
func eyes_by_domain(command_list []string) string {
	db := database.GetDatabase()
	if len(command_list) == 2 {
		groups, err := domain.GetGroupsUnderDomain(command_list[1], db)
		if err != nil {
			logs.Write_Log("ERROR", "Error retrieving groups: "+err.Error())
		}
		output := "\nGroups under domain " + command_list[1] + ":\n"
		for _, group := range groups {
			output += group + "\n"
		}
		if len(groups) == 0 {
			return "Domaine non trouvé ou aucun groupe associé."
		}
		return output
	}
	groups, err := database.GetAllGroupsWithDomains(db)
	if err != nil {
		return "Erreur lors de la récupération des groupes : " + err.Error()
	}

	tree := domain.BuildDomainTree(groups)

	output := display.PrintDomainTreeRoot(tree)

	if output == "" {
		return "Aucune donnée disponible."
	}

	return output
}
