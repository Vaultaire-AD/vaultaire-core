package filter

import (
	"fmt"
	"strings"
	ldapinterface "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate/ldap_interface"
	"vaultaire/core/logs"
)

func evalPresent(entry ldapinterface.LDAPEntry, attr string) bool {
	attr = strings.TrimSpace(strings.ToLower(attr))

	// Si l'attribut est vide, match toutes les entrées
	if attr == "" {
		logs.Write_Log("DEBUG", fmt.Sprintf("Present filter with empty attribute => match all for DN=%s", entry.DN()))

		return true
	}

	// objectClass est toujours présent
	if attr == "objectclass" {
		return true
	}

	values := entry.GetAttribute(attr)
	match := len(values) > 0
	logs.Write_Log("DEBUG", fmt.Sprintf("Present filter check for DN=%s attr=%s => match=%v (values=%v)", entry.DN(), attr, match, values))

	return match
}
