package permission

import (
	"vaultaire/serveur/storage"
	"strings"
)

// UpdatePermissionAction met à jour une PermissionAction selon -a ou -r
// Passage obligatoire en mode custom quand on passe par cette fonction
func UpdatePermissionAction(pa *storage.PermissionAction, domain string, childOrAll string, add bool) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return
	}
	pa.Type = "custom"
	targetList := &pa.WithoutPropagation
	if childOrAll == "-c" || childOrAll == "child" || childOrAll == "1" {
		targetList = &pa.WithPropagation
	}

	if add {
		// Ajouter domaine si pas déjà présent
		for _, d := range *targetList {
			if d == domain {
				return
			}
		}
		*targetList = append(*targetList, domain)
	} else {
		// Supprimer domaine si présent
		newList := []string{}
		for _, d := range *targetList {
			if d != domain {
				newList = append(newList, d)
			}
		}
		*targetList = newList
	}
}
