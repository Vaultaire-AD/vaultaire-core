package candidate

import (
	"fmt"
	"strings"
	ldaptools "vaultaire/core/ldap/LDAP-TOOLS"
)

type GroupEntry struct {
	Name    string
	BaseDN  string
	Members []string
}

func (g GroupEntry) DN() string {
	return fmt.Sprintf("cn=%s,ou=groups,%s", g.Name, ldaptools.ToRootDN(g.BaseDN))
}

func (g GroupEntry) ObjectClasses() []string {
	return []string{
		"top",
		"groupOfNames",
		"posixGroup",
		"group",              // <- ajouté pour Nextcloud
		"organizationalUnit", // si tu veux
	}
}

// Méthode complète pour gérer "*", "+", TypesOnly
func (g GroupEntry) GetAttributes(requested []string, typesOnly bool) map[string][]string {
	all := map[string][]string{
		"dn": {g.DN()},
		"cn": {g.Name},
		// "ou":          {"groups"},
		"displayname": {g.Name},
		"member":      g.Members,
		"objectclass": g.ObjectClasses(),
	}

	result := make(map[string][]string)
	includeAll := len(requested) == 0 || contains(requested, "*")
	includeOperational := contains(requested, "+")

	for k, v := range all {
		// Aucun attribut opérationnel sur un groupe aujourd'hui : la branche est
		// donc inerte. Elle est alignée sur celle des utilisateurs quand même,
		// parce que la version inversée qui s'y trouvait aurait diffusé le premier
		// attribut opérationnel ajouté ici — silencieusement, et sur toutes les
		// recherches.
		if isOperational(k) && !includeOperational && !contains(requested, k) {
			continue
		}

		if includeAll || contains(requested, k) || (includeOperational && isOperational(k)) {
			if typesOnly {
				result[k] = []string{}
			} else {
				result[k] = v
			}
		}
	}

	return result
}

func (g GroupEntry) GetAttribute(attr string) []string {
	attr = strings.ToLower(attr)
	res := g.GetAttributes([]string{attr}, false)
	return res[attr]
}
