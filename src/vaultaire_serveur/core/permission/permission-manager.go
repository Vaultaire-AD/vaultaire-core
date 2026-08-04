package permission

import (
	"fmt"
	"strings"
	"vaultaire/core/database"
	dbpermission "vaultaire/core/database/db_permission"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
)

// CheckPermissionsMultipleDomains vérifie si un ou plusieurs groupes ont le droit d'effectuer une action
// sur une liste de domaines donnés.
// Retourne :
// - bool : true si au moins un domaine est autorisé
// - string : résumé textuel
//
// Niveaux de log : DEBUG pour le déroulé normal (silencieux par défaut, activable via storage.Debug
// dans l'admin), WARNING pour un refus ou une action invalide (visible par défaut, utile pour l'audit
// sécurité), ERROR uniquement pour un vrai problème système (DB indisponible, etc.).
func CheckPermissionsMultipleDomains(groupIDs []int, action string, domainsToCheck []string) (bool, string) {
	anyAllowed := false
	var sb strings.Builder

	// Vérifier validité de l’action
	action, ok := IsValidAction(action)
	if !ok {
		for _, domain := range domainsToCheck {
			logs.Write_LogCode("WARNING", logs.CodeAuthPermission,
				fmt.Sprintf("Action '%s' non valide pour le domaine '%s'", action, domain))
			sb.WriteString(fmt.Sprintf("Action '%s' non valide sur %s", action, domain))
		}
		return false, sb.String()
	}
	var parsedPermission storage.ParsedPermission

	// Cas spécial : aucun domaine à vérifier => on vérifie seulement le super admin (All)
	if len(domainsToCheck) == 0 {
		for _, groupID := range groupIDs {
			content, err := dbpermission.GetPermissionContent(database.GetDatabase(), groupID, action)
			if err != nil {
				logs.Write_LogCode("ERROR", logs.CodeDBQuery,
					fmt.Sprintf("Erreur récupération permission pour le groupe %d: %v", groupID, err))
				continue
			}

			parsedPermission := ParsePermissionContent(content)
			if parsedPermission.All {
				logs.Write_LogCode("DEBUG", logs.CodeNone,
					fmt.Sprintf("Action '%s' autorisée partout (*) via groupe %d (super admin)", action, groupID))
				return true, fmt.Sprintf("Permission super admin via groupe %d", groupID)
			}
		}
		logs.Write_LogCode("WARNING", logs.CodeAuthLoginDenied,
			fmt.Sprintf("Action '%s' refusée (aucun domaine et pas de super admin)", action))
		return false, "Refusée : aucun domaine pour l'entité et aucun super admin"
	}

	for _, domain := range domainsToCheck {
		allowed := false
		for _, groupID := range groupIDs {
			logs.Write_LogCode("DEBUG", logs.CodeNone,
				fmt.Sprintf("Vérification de la permission pour le groupe ID %d, action '%s' sur le domaine '%s'", groupID, action, domain))
			content, err := dbpermission.GetPermissionContent(database.GetDatabase(), groupID, action)
			if err != nil {
				logs.Write_LogCode("ERROR", logs.CodeDBQuery,
					fmt.Sprintf("Erreur récupération permission pour le groupe %d: %v", groupID, err))
				continue
			}

			logs.Write_LogCode("DEBUG", logs.CodeNone,
				fmt.Sprintf("Permission brute pour le groupe %d, action '%s': %s", groupID, action, content))
			parsedPermission = ParsePermissionContent(content)

			if parsedPermission.Deny {
				continue
			}

			if parsedPermission.All {
				logs.Write_LogCode("DEBUG", logs.CodeNone,
					fmt.Sprintf("Action '%s' autorisée partout (*) via groupe %d", action, groupID))
				sb.WriteString(fmt.Sprintf("%s : autorisée partout (*) via groupe %d", domain, groupID))
				allowed = true
				break
			}

			for _, d := range parsedPermission.NoPropagation {
				if domain == d {
					logs.Write_LogCode("DEBUG", logs.CodeNone,
						fmt.Sprintf("Action '%s' autorisée uniquement sur %s (sans propagation) via groupe %d", action, domain, groupID))
					sb.WriteString(fmt.Sprintf("%s : autorisée (sans propagation) via groupe %d", domain, groupID))
					allowed = true
					break
				}
			}
			if allowed {
				break
			}

			for _, d := range parsedPermission.WithPropagation {
				if domain == d || strings.HasSuffix(domain, "."+d) {
					logs.Write_LogCode("DEBUG", logs.CodeNone,
						fmt.Sprintf("Action '%s' autorisée sur %s (avec propagation depuis %s) via groupe %d", action, domain, d, groupID))
					sb.WriteString(fmt.Sprintf("%s : autorisée (avec propagation depuis %s) via groupe %d", domain, d, groupID))
					allowed = true
					break
				}
			}
			if allowed {
				break
			}
		}

		if !allowed {
			logs.Write_LogCode("WARNING", logs.CodeAuthLoginDenied, fmt.Sprintf(
				"Action '%s' refusée sur le domaine '%s' (aucune règle applicable dans les groupes %v)",
				action, domain, groupIDs,
			))
			sb.WriteString(fmt.Sprintf("%s : refusée", domain))
		} else {
			anyAllowed = true
		}
	}

	return anyAllowed, sb.String()
}
