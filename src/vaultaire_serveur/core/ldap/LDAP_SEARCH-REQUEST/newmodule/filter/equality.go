package filter

import (
	"strings"
	ldapinterface "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate/ldap_interface"
)

func evalEquality(entry ldapinterface.LDAPEntry, attr, value string) bool {
	attr = strings.ToLower(strings.TrimSpace(attr))
	value = strings.TrimSpace(value)

	// Many clients (JumpServer, AD tools) send (attr=*) as equality, not present
	if value == "*" {
		return evalPresent(entry, attr)
	}

	for _, v := range entry.GetAttribute(attr) {
		if strings.EqualFold(strings.TrimSpace(v), value) {
			return true
		}
	}
	return false
}
