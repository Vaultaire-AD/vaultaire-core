package candidate

import (
	ldaptools "vaultaire/serveur/ldap/LDAP-TOOLS"
	"fmt"
	"strings"
)

type GroupEntry struct {
	Name    string
	BaseDN  string
	Members []string
}

func (g GroupEntry) DN() string {
	return fmt.Sprintf("cn=%s,ou=groups,%s", g.Name, ldaptools.DomainToDC(g.BaseDN))
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
		"displyname":  {g.Name},
		"member":      g.Members,
		"objectclass": g.ObjectClasses(),
	}

	result := make(map[string][]string)
	includeAll := len(requested) == 0 || contains(requested, "*")
	includeOperational := contains(requested, "+")

	for k, v := range all {
		// Pas de champs opérationnels pour l'instant, mais placeholder si besoin
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

func (g GroupEntry) GetAttribute(attr string) []string {
	attr = strings.ToLower(attr)
	res := g.GetAttributes([]string{attr}, false)
	return res[attr]
}
