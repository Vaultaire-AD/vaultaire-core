package ldaptools

import (
	ldapstorage "DUCKY/serveur/ldap/LDAP_Storage"
	"strings"
)

// DetectKeywordCategories analyse les filtres LDAP et détecte les catégories (user, group, CN=Users, etc.)
// en tenant compte de CN=Users pour déclencher la récupération de tous les utilisateurs via les groupes
func DetectKeywordCategories(filters []ldapstorage.EqualityFilter, keywordMap map[string][]string) map[string]bool {
	found := make(map[string]bool)

	for _, f := range filters {
		attr := strings.ToLower(strings.TrimSpace(f.Attribute))
		value := strings.TrimSpace(f.Value)

		// --- Vérification CN spécifique ---
		for _, kw := range keywordMap["CN"] {
			if strings.EqualFold(value, kw) {
				found["CN"] = true
				break
			}
		}

		// --- Vérification objectClass ---
		if attr == "objectclass" {
			for _, kw := range keywordMap["user"] {
				if strings.EqualFold(value, kw) {
					found["user"] = true
					break
				}
			}
			for _, kw := range keywordMap["group"] {
				if strings.EqualFold(value, kw) {
					found["group"] = true
					break
				}
			}
		}

		// --- Vérification uid ---
		if attr == "uid" {
			found["uid"] = true
		}

		// --- Vérification member ---
		if attr == "member" {
			found["group"] = true
		}
	}

	return found
}
