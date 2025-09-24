package permission

import (
	"DUCKY/serveur/database"
	"DUCKY/serveur/database/db_permission"
	"fmt"
	"strings"
)

// -u -g -gpo

// CheckPermission va vérifier si un groupe a le droit d'effectuer une action sur un domaine donné
// Pour l'instant, aucune logique, juste la structure
func CheckPermission(groupID int, action string, domain string) (bool, string) {
	// Variables de base
	var message string // message d'erreur ou d'information

	// Pour l'instant, juste un retour par défaut
	message = fmt.Sprintf("Action '%s' sur le domaine '%s' pour le groupe %d non encore implémentée", action, domain, groupID)
	action, ok := IsValidAction(action)
	if !ok {
		message = fmt.Sprintf("Action '%s' non valide contacter l'editeur erreur dans le code source", action)
		return false, message
	}
	content, err := db_permission.GetPermissionContent(database.GetDatabase(), groupID, action)
	if err != nil {
		message = fmt.Sprintf("Erreur lors de la récupération des permissions: %v", err)
		return false, message
	}

	parsedPermission := ParsePermissionContent(content)

	// Cas deny → toujours false
	if parsedPermission.Deny {
		return false, fmt.Sprintf("Action '%s' refusée : permission désactivée (nil)", action)
	}

	// Cas all → toujours true
	if parsedPermission.All {
		return true, fmt.Sprintf("Action '%s' autorisée partout (*)", action)
	}

	// Vérifier NoPropagation (0)
	for _, d := range parsedPermission.NoPropagation {
		if domain == d {
			return true, fmt.Sprintf("Action '%s' autorisée uniquement sur le domaine %s (sans propagation)", action, domain)
		}
	}

	// Vérifier WithPropagation (1)
	for _, d := range parsedPermission.WithPropagation {
		if domain == d || strings.HasSuffix(domain, "."+d) {
			return true, fmt.Sprintf("Action '%s' autorisée sur %s (avec propagation depuis %s)", action, domain, d)
		}
	}

	// Sinon refus par défaut
	return false, fmt.Sprintf("Action '%s' refusée sur le domaine '%s' (aucune règle applicable)", action, domain)
}
