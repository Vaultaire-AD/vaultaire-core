package permission

import (
	"DUCKY/serveur/database"
	"DUCKY/serveur/database/db_permission"
	"DUCKY/serveur/logs"
	"DUCKY/serveur/storage"
	"fmt"
	"strings"
)

// CheckPermissionsMultipleDomains vérifie si un ou plusieurs groupes ont le droit d'effectuer une action
// sur une liste de domaines donnés.
// Retourne :
// - bool : true si au moins un domaine est autorisé
// - string : résumé textuel
func CheckPermissionsMultipleDomains(groupIDs []int, action string, domainsToCheck []string) (bool, string) {
	anyAllowed := false
	var sb strings.Builder

	// Vérifier validité de l’action
	action, ok := IsValidAction(action)
	if !ok {
		for _, domain := range domainsToCheck {
			logs.Write_Log("DEBUG", fmt.Sprintf("Action '%s' non valide pour le domaine '%s'", action, domain))
			sb.WriteString(fmt.Sprintf("Action '%s' non valide sur %s\n", action, domain))
		}
		return false, sb.String()
	}
	var parsedPermission storage.ParsedPermission
	for _, domain := range domainsToCheck {
		allowed := false
		for _, groupID := range groupIDs {
			logs.Write_Log("DEBUG", fmt.Sprintf("Vérification de la permission pour le groupe ID %d, action '%s' sur le domaine '%s'", groupID, action, domain))
			content, err := db_permission.GetPermissionContent(database.GetDatabase(), groupID, action)
			if err != nil {
				logs.Write_Log("ERROR", fmt.Sprintf("Erreur récupération permission pour le groupe %d: %v", groupID, err))
				continue
			}

			logs.Write_Log("DEBUG", fmt.Sprintf("Permission brute pour le groupe %d, action '%s': %s", groupID, action, content))
			parsedPermission = ParsePermissionContent(content)

			if parsedPermission.Deny {
				continue
			}

			if parsedPermission.All {
				logs.Write_Log("DEBUG", fmt.Sprintf("Action '%s' autorisée partout (*) via groupe %d", action, groupID))
				sb.WriteString(fmt.Sprintf("%s : autorisée partout (*) via groupe %d\n", domain, groupID))
				allowed = true
				break
			}

			for _, d := range parsedPermission.NoPropagation {
				if domain == d {
					logs.Write_Log("DEBUG", fmt.Sprintf("Action '%s' autorisée uniquement sur %s (sans propagation) via groupe %d", action, domain, groupID))
					sb.WriteString(fmt.Sprintf("%s : autorisée (sans propagation) via groupe %d\n", domain, groupID))
					allowed = true
					break
				}
			}
			if allowed {
				break
			}

			for _, d := range parsedPermission.WithPropagation {
				if domain == d || strings.HasSuffix(domain, "."+d) {
					logs.Write_Log("DEBUG", fmt.Sprintf("Action '%s' autorisée sur %s (avec propagation depuis %s) via groupe %d", action, domain, d, groupID))
					sb.WriteString(fmt.Sprintf("%s : autorisée (avec propagation depuis %s) via groupe %d\n", domain, d, groupID))
					allowed = true
					break
				}
			}
			if allowed {
				break
			}
		}

		if !allowed {
			logs.Write_Log("DEBUG", fmt.Sprintf(
				"Action '%s' refusée sur le domaine '%s' (aucune règle applicable dans les groupes %v) - ParsedPermission: %+v",
				action, domain, groupIDs, parsedPermission,
			))
			sb.WriteString(fmt.Sprintf("%s : refusée\n", domain))
		} else {
			anyAllowed = true
		}
	}

	return anyAllowed, sb.String()
}
