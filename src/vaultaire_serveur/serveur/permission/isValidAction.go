package permission

import "strings"

// Liste des actions possibles (colonnes de la table user_permission_test)
var validActions = []string{
	"none",
	"web_admin",
	"auth",
	"compare",
	"search",
	"can_read",
	"can_write",
	"api_read_permission",
	"api_write_permission",
}

// IsValidAction vérifie si une action est valide
func IsValidAction(action string) (string, bool) {
	action = strings.ToLower(action) // pour éviter les problèmes de casse
	for _, a := range validActions {
		if a == action {
			return a, true
		}
	}
	return action, false
}
