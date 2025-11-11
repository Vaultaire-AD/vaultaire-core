package ldaptools

import (
	ldapstorage "DUCKY/serveur/ldap/LDAP_Storage"
	"strings"
)

func DetectKeywordCategories(filters []ldapstorage.EqualityFilter, keywordMap map[string][]string) map[string]bool {
	found := make(map[string]bool)

	for _, f := range filters {
		attr := strings.ToLower(f.Attribute)
		value := strings.ToLower(f.Value)

		// Si l'attribut est "objectClass", on compare avec les mots-clés correspondants
		if attr == "objectclass" {
			for _, kw := range keywordMap["user"] {
				if value == strings.ToLower(kw) {
					found["user"] = true
					break
				}
			}
			for _, kw := range keywordMap["group"] {
				if value == strings.ToLower(kw) {
					found["group"] = true
					break
				}
			}
		}

		// Si l'attribut est "uid", on considère que c’est une recherche utilisateur
		if attr == "uid" {
			found["uid"] = true
		}
		if attr == "member" {
			found["group"] = true
		}
		for _, kw := range keywordMap["user"] {
			if value == strings.ToLower(kw) {
				found["user"] = true
				break
			}
		}

	}

	return found
}
