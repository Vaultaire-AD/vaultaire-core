package ldapsearchrequest

import (
	ldapstorage "vaultaire/serveur/ldap/LDAP_Storage"
	"fmt"
)

func ExtractEqualityFilters(filter *ldapstorage.LDAPFilter) ([]ldapstorage.EqualityFilter, error) {
	if filter == nil {
		return nil, fmt.Errorf("nil LDAP filter")
	}

	var result []ldapstorage.EqualityFilter

	var walk func(f *ldapstorage.LDAPFilter)
	walk = func(f *ldapstorage.LDAPFilter) {
		if f == nil {
			return
		}

		switch f.Type {

		case ldapstorage.FilterEquality:
			result = append(result, ldapstorage.EqualityFilter{
				Attribute: f.Attribute,
				Value:     f.Value,
			})

		case ldapstorage.FilterPresent:
			result = append(result, ldapstorage.EqualityFilter{
				Attribute: f.Attribute,
				Value:     "*",
			})

		case ldapstorage.FilterAnd,
			ldapstorage.FilterOr,
			ldapstorage.FilterNot:
			for _, child := range f.SubFilters {
				walk(child)
			}
		}
	}

	walk(filter)
	return result, nil
}

func isGenericSearch(filters []ldapstorage.EqualityFilter) bool {
	// Si pas de filtres, ou si le seul filtre est objectClass=*
	if len(filters) == 0 {
		return true
	}
	if len(filters) == 1 {
		attr := filters[0].Attribute
		val := filters[0].Value
		if (attr == "objectclass" || attr == "objectClass") && (val == "*" || val == "top") {
			return true
		}
	}
	return false
}
