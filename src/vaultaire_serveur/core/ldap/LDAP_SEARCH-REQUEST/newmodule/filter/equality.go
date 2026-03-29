package filter

import (
	"fmt"
	"strings"
	ldapinterface "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate/ldap_interface"
)

func evalEquality(entry ldapinterface.LDAPEntry, attr, value string) bool {
	attr = strings.ToLower(strings.TrimSpace(attr))
	value = strings.TrimSpace(value)

	vals := entry.GetAttribute(attr)

	// LOG DE DIAGNOSTIC
	if attr == "uid" || attr == "cn" {
		fmt.Printf("[DEBUG-FILTER] DN: %s | Attr: %s | Comparaison: '%s' == '%v'\n",
			entry.DN(), attr, value, vals)
	}

	for _, v := range vals {
		if strings.EqualFold(strings.TrimSpace(v), value) {
			return true
		}
	}
	return false
}
