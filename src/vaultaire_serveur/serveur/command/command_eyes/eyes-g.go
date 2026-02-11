package commandeyes

import (
	"vaultaire/serveur/command/display"
	"vaultaire/serveur/database"
	"vaultaire/serveur/domain"
	"vaultaire/serveur/logs"
	"vaultaire/serveur/permission"
	"fmt"
	"strings"
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
func eyes_by_domain(command_list []string, sender_groupsIDs []int, action, sender_Username string) string {
	db := database.GetDatabase()

	var targetDomains []string
	if len(command_list) == 2 {
		targetDomains = []string{command_list[1]}
	} else {
		targetDomains = []string{"*"}
	}

	// Vérification centralisée des permissions
	ok, response := permission.CheckPermissionsMultipleDomains(sender_groupsIDs, action, targetDomains)
	if !ok {
		logs.Write_Log("WARNING", fmt.Sprintf("Permission refused: user=%s action=%s reason=%s", sender_Username, action, response))
		return "Permission refusée : " + response
	}
	logs.Write_Log("INFO", fmt.Sprintf("Permission used: user=%s action=%s (eyes tree)", sender_Username, action))

	// Si un domaine spécifique est fourni
	if len(command_list) == 2 {
		groups, err := domain.GetGroupsUnderDomain(command_list[1], db, true)
		if err != nil {
			logs.Write_Log("ERROR", "Erreur lors de la récupération des groupes : "+err.Error())
			return "Erreur interne lors de la récupération des groupes."
		}

		if len(groups) == 0 {
			return "Domaine non trouvé ou aucun groupe associé."
		}

		var sb strings.Builder
		sb.WriteString("\nGroups under domain " + command_list[1] + ":\n")
		for _, group := range groups {
			sb.WriteString(group + "\n")
		}
		return sb.String()
	}

	// Sinon récupérer tous les groupes pour tous les domaines
	allGroups, err := database.GetAllGroupsWithDomains(db)
	if err != nil {
		logs.Write_Log("ERROR", "Erreur lors de la récupération de tous les groupes : "+err.Error())
		return "Erreur lors de la récupération des groupes : " + err.Error()
	}

	tree := domain.BuildDomainTree(allGroups)
	output := display.PrintDomainTreeRoot(tree)

	if output == "" {
		return "Aucune donnée disponible."
	}
	return output
}
