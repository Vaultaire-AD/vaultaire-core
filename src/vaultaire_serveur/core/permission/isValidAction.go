package permission

import (
	"strings"
)

// Objets et actions RBAC (catégorie:action:objet)
var (
	RBACObjects   = []string{"user", "group", "client", "permission", "gpo"}
	RBACRead      = []string{"get", "status"}
	RBACWrite     = []string{"create", "delete", "update", "add"}
	legacyActions = []string{"none", "web_admin", "auth", "compare", "search"}

	// specialActions sont les commandes qui ne se rangent pas dans le modèle
	// catégorie:action:objet. Elles étaient énumérées à trois endroits (ici,
	// l'interface web, le CLI) : la liste vit désormais ici seule, sinon en
	// ajouter une la rendrait invisible dans l'interface sans que rien ne le
	// signale.
	specialActions = []string{"write:dns", "write:eyes"}
)

// globalOnlyActions sont les actions dont le contrôle passe toujours le domaine
// « * », quelle que soit la cible.
//
// Leur donner une liste de domaines ne les restreint pas : cela les refuse,
// puisque aucun domaine nommé ne correspond à « * ». Pour web_admin la
// conséquence est brutale — l'auteur du changement perd l'accès à l'interface
// d'administration, y compris pour se corriger.
//
// Vérifié aux appelants : web_admin dans web_serveur/web_admin.go et
// web_profil.go, write:dns dans command_dns/command_dns_manager.go. Si un de ces
// appels venait à transmettre un domaine réel, il faudrait retirer l'entrée
// correspondante ici.
var globalOnlyActions = []string{"web_admin", "write:dns"}

// IsGlobalOnlyAction dit si une action ne s'évalue que sur « * », et n'accepte
// donc que nil ou all.
func IsGlobalOnlyAction(key string) bool {
	for _, a := range globalOnlyActions {
		if a == key {
			return true
		}
	}
	return false
}

// LegacyActionKeys retourne les actions historiques, hors modèle RBAC.
func LegacyActionKeys() []string { return append([]string(nil), legacyActions...) }

// SpecialActionKeys retourne les commandes spéciales, hors modèle RBAC.
func SpecialActionKeys() []string { return append([]string(nil), specialActions...) }

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
	list = append(list, specialActions...)
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
