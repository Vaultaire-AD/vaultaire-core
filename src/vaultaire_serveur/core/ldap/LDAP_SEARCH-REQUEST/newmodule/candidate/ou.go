package candidate

import (
	"fmt"
	"strings"
	ldaptools "vaultaire/core/ldap/LDAP-TOOLS"
)

// OUEntry représente une Organizational Unit fictive
type OUEntry struct {
	Name   string // "users" ou "groups"
	BaseDN string // domaine parent
}

func (ou OUEntry) DN() string {
	return fmt.Sprintf("ou=%s,%s", ou.Name, ldaptools.ToRootDN(ou.BaseDN))
}

// Domaines — voir ldapinterface.LDAPEntry.
//
// Une OU est fabriquée pour un domaine donné : `users` et `groups` sont créées
// une fois par domaine parcouru, et `BaseDN` est ce domaine-là.
func (ou OUEntry) Domaines() []string {
	if ou.BaseDN == "" {
		return nil
	}
	return []string{ou.BaseDN}
}

func (ou OUEntry) ObjectClasses() []string {
	return []string{"top", "organizationalUnit"}
}

func (ou OUEntry) GetAttributes(requested []string, typesOnly bool) map[string][]string {
	all := map[string][]string{
		"dn":          {ou.DN()},
		"ou":          {ou.Name},
		"cn":          {ou.Name},
		"objectclass": ou.ObjectClasses(),
	}
	result := make(map[string][]string)
	includeAll := len(requested) == 0 || contains(requested, "*")
	for k, v := range all {
		if includeAll || contains(requested, k) {
			if typesOnly {
				result[k] = []string{}
			} else {
				result[k] = v
			}
		}
	}
	return result
}

func (ou OUEntry) GetAttribute(attr string) []string {
	attr = strings.ToLower(attr)
	res := ou.GetAttributes([]string{attr}, false)
	return res[attr]
}
