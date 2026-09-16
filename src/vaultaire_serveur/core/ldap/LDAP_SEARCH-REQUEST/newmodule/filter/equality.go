package filter

import (
	"fmt"
	"strings"
	ldapinterface "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate/ldap_interface"
	"vaultaire/core/logs"
)

func evalEquality(entry ldapinterface.LDAPEntry, attr, value string) bool {
	attr = strings.ToLower(strings.TrimSpace(attr))
	value = strings.TrimSpace(value)

	// Many clients (JumpServer, AD tools) send (attr=*) as equality, not present
	if value == "*" {
		return evalPresent(entry, attr)
	}

	vals := entry.GetAttribute(attr)

	// LOG DE DIAGNOSTIC
	if attr == "uid" || attr == "cn" {
		logs.Write_Log("DEBUG", fmt.Sprintf("Equality filter check for DN=%s attr=%s value='%s' entry values=%v",
			entry.DN(), attr, value, vals))

	}

	for _, v := range vals {
		if strings.EqualFold(strings.TrimSpace(v), value) {
			return true
		}
	}
	return false
}
