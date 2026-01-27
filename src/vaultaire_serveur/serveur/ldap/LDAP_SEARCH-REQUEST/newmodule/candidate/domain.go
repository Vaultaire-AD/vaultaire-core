package candidate

import (
	"strings"
)

// DomainEntry représente le domaine lui-même en tant qu'entrée LDAP
type DomainEntry struct {
	DNName string
}

func (d DomainEntry) DN() string {
	return d.DNName
}

func (d DomainEntry) ObjectClasses() []string {
	return []string{"top", "domain"}
}

// GetAttribute pour compat interface LDAPEntry
func (d DomainEntry) GetAttribute(attr string) []string {
	attr = strings.ToLower(attr)
	all := d.GetAttributes([]string{attr}, false)
	if vals, ok := all[strings.ToLower(attr)]; ok {
		return vals
	}
	return nil
}

// GetAttributes pour gérer liste d'attributs et '*'
func (d DomainEntry) GetAttributes(requested []string, typesOnly bool) map[string][]string {
	all := map[string][]string{
		"objectclass": {"top", "domain"},
		"dc":          {d.getDC()},
		"dn":          {d.DN()},
	}

	result := make(map[string][]string)
	includeAll := len(requested) == 0 || contains(requested, "*")
	includeOperational := contains(requested, "+")

	for k, v := range all {
		if isOperational(k) && !includeOperational {
			// Ne pas skip si on a une vraie valeur
			if len(v) > 0 {
				result[k] = v
			}
			continue
		}
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
func (d DomainEntry) getDC() string {
	parts := strings.Split(d.DNName, ".")
	if len(parts) > 0 {
		return parts[0]
	}
	return d.DNName
}
