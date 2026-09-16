package ldaptools

import "strings"

var MandatoryUserAttrs = []string{
	"uid", "cn", "sn", "displayName", "objectClass",
}

var MandatoryGroupAttrs = []string{
	"cn", "member", "objectClass",
}

// mergeAttributes fusionne les attributs demandés et les attributs obligatoires
// sans doublons. Si un attribut est déjà présent, il n'est pas ajouté une deuxième fois.
func MergeAttributes(requestedAttrs, mandatoryAttrs []string) []string {
	// map pour détecter les doublons
	seen := make(map[string]struct{})

	result := []string{}

	// ajouter d'abord les attributs demandés
	for _, attr := range requestedAttrs {
		key := strings.ToLower(attr) // éviter doublons avec casse différente
		if _, exists := seen[key]; !exists {
			result = append(result, attr)
			seen[key] = struct{}{}
		}
	}

	// ajouter les attributs obligatoires s'ils ne sont pas déjà présents
	for _, attr := range mandatoryAttrs {
		key := strings.ToLower(attr)
		if _, exists := seen[key]; !exists {
			result = append(result, attr)
			seen[key] = struct{}{}
		}
	}

	return result
}
