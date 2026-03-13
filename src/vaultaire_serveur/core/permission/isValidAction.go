package permission

import (
	"strings"
)

// Objets et actions RBAC (catégorie:action:objet)
var (
	RBACObjects  = []string{"user", "group", "client", "permission", "gpo"}
	RBACRead     = []string{"get", "status"}
	RBACWrite    = []string{"create", "delete", "update", "add"}
	legacyActions = []string{"none", "web_admin", "auth", "compare", "search"}
)

// Liste des actions valides (legacy + RBAC)
var validActions = buildValidActions()

func buildValidActions() []string {
	list := make([]string, 0, 50)
	list = append(list, legacyActions...)
	for _, obj := range RBACObjects {
		for _, a := range RBACRead {
			list = append(list, "read:"+a+":"+obj)
		}
		for _, a := range RBACWrite {
			list = append(list, "write:"+a+":"+obj)
		}
	}
	list = append(list, "write:dns", "write:eyes") // commandes spéciales
	return list
}

// IsValidAction vérifie si une action est valide et retourne le nom normalisé
func IsValidAction(action string) (string, bool) {
	action = strings.ToLower(action)
	for _, a := range validActions {
		if a == action {
			return a, true
		}
	}
	// Accepte aussi le format catégorie:action:objet si cohérent
	if IsRBACActionKey(action) {
		return action, true
	}
	return action, false
}

// IsRBACActionKey retourne true si la chaîne respecte le format catégorie:action:objet
func IsRBACActionKey(key string) bool {
	parts := strings.Split(key, ":")
	if len(parts) != 3 {
		return false
	}
	cat, act, obj := strings.ToLower(parts[0]), strings.ToLower(parts[1]), strings.ToLower(parts[2])
	if cat != "read" && cat != "write" {
		return false
	}
	objOk := false
	for _, o := range RBACObjects {
		if o == obj {
			objOk = true
			break
		}
	}
	if !objOk {
		return false
	}
	if cat == "read" {
		for _, a := range RBACRead {
			if a == act {
				return true
			}
		}
	}
	if cat == "write" {
		for _, a := range RBACWrite {
			if a == act {
				return true
			}
		}
	}
	return false
}

// AllRBACActionKeys retourne la liste de toutes les clés RBAC (pour l'admin)
func AllRBACActionKeys() []string {
	var keys []string
	for _, obj := range RBACObjects {
		for _, a := range RBACRead {
			keys = append(keys, "read:"+a+":"+obj)
		}
		for _, a := range RBACWrite {
			keys = append(keys, "write:"+a+":"+obj)
		}
	}
	return keys
}
