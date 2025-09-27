package permission

import (
	"DUCKY/serveur/database"
	"DUCKY/serveur/database/db_permission"
	"DUCKY/serveur/logs"
	"fmt"
	"strings"
)

// CheckPermission va vérifier si un OU plusieurs groupes ont le droit d'effectuer une action sur un domaine donné
func CheckPermission(groupIDs []int, action string, domaintocheck string) (bool, string) {
	// Vérifier validité de l’action
	action, ok := IsValidAction(action)
	if !ok {
		return false, fmt.Sprintf("Action '%s' non valide contacter l'éditeur (erreur code source)", action)
	}

	// On itère sur chaque groupe → si un seul autorise, on return true immédiatement
	for _, groupID := range groupIDs {
		logs.Write_Log("DEBUG", fmt.Sprintf("Vérification de la permission pour le groupe ID %d, action '%s' sur le domaine '%s'", groupID, action, domaintocheck))
		content, err := db_permission.GetPermissionContent(database.GetDatabase(), groupID, action)
		if err != nil {
			// Ici on log l'erreur mais on ne bloque pas forcément (un autre groupe peut donner la permission)
			logs.Write_Log("ERROR", fmt.Sprintf("Erreur lors de la récupération du contenu de la permission pour le groupe %d: %v", groupID, err))
			continue
		}

		parsedPermission := ParsePermissionContent(content)

		// Cas deny → ce groupe ne donne aucun droit
		if parsedPermission.Deny {
			continue
		}

		// Cas all → autorisé partout
		if parsedPermission.All {
			return true, fmt.Sprintf("Action '%s' autorisée partout (*) via groupe %d", action, groupID)
		}

		// Vérifier NoPropagation (0) → match exact
		for _, d := range parsedPermission.NoPropagation {
			if domaintocheck == d {
				return true, fmt.Sprintf("Action '%s' autorisée uniquement sur %s (sans propagation) via groupe %d", action, domaintocheck, groupID)
			}
		}

		// Vérifier WithPropagation (1) → domaine exact ou sous-domaine
		for _, d := range parsedPermission.WithPropagation {
			if domaintocheck == d || strings.HasSuffix(domaintocheck, "."+d) {
				return true, fmt.Sprintf("Action '%s' autorisée sur %s (avec propagation depuis %s) via groupe %d", action, domaintocheck, d, groupID)
			}
		}
	}

	// Si aucun groupe n'autorise → refus
	return false, fmt.Sprintf("Action '%s' refusée sur le domaine '%s' (aucune règle applicable dans les groupes %v)", action, domaintocheck, groupIDs)
}
