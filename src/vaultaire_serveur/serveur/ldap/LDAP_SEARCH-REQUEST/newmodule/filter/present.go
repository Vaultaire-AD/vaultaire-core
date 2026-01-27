package filter

import (
	ldapinterface "DUCKY/serveur/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate/ldap_interface"
	"fmt"
	"strings"
)

func evalPresent(entry ldapinterface.LDAPEntry, attr string) bool {
	attr = strings.TrimSpace(strings.ToLower(attr))

	// Si l'attribut est vide, match toutes les entrées
	if attr == "" {
		fmt.Printf("[DEBUG] Present empty attribute => match tout pour DN=%s\n", entry.DN())
		return true
	}

	// objectClass est toujours présent
	if attr == "objectclass" {
		return true
	}

	values := entry.GetAttribute(attr)
	match := len(values) > 0
	fmt.Printf("[DEBUG] Present check DN=%s attr=%s values=%v => %v\n", entry.DN(), attr, values, match)
	return match
}
