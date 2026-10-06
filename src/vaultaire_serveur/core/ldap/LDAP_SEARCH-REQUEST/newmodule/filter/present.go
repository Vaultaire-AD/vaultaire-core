package filter

import (
	"strings"
	ldapinterface "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate/ldap_interface"
)

func evalPresent(entry ldapinterface.LDAPEntry, attr string) bool {
	attr = strings.TrimSpace(strings.ToLower(attr))

	// Si l'attribut est vide, match toutes les entrées
	if attr == "" {
		return true
	}

	// objectClass est toujours présent
	if attr == "objectclass" {
		return true
	}

	// Sans ligne de journal (TO-DO 145) : celle qui se trouvait ici sortait
	// une fois par entrée ET par nœud de filtre, avec les valeurs de l'attribut.
	return len(entry.GetAttribute(attr)) > 0
}
