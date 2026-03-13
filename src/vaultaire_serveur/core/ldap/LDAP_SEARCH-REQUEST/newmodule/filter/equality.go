package filter

import (
	"strings"
	ldapinterface "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate/ldap_interface"
)

func evalEquality(entry ldapinterface.LDAPEntry, attr, value string) bool {
	attr = strings.ToLower(strings.TrimSpace(attr))
	value = strings.TrimSpace(value)

	vals := entry.GetAttribute(attr)
	for _, v := range vals {
		if strings.EqualFold(v, value) { // case-insensitive matching
			return true
		}
	}
	return false
}
