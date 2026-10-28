package candidate

import (
	"strings"

	ldaptools "vaultaire/core/ldap/LDAP-TOOLS"
)

// DomainEntry représente le domaine lui-même en tant qu'entrée LDAP
type DomainEntry struct {
	DNName string
	// Feuille : le domaine n'a aucun enfant dans l'arbre — ni sous-domaine, ni
	// OU (elles ne sont que sous la racine). Rendu par `hasSubordinates`.
	// Faux par défaut : un domaine dont on ne sait rien est dit ouvrable.
	Feuille bool
}

func (d DomainEntry) DN() string {
	if strings.Contains(d.DNName, "=") {
		return d.DNName
	}
	return ldaptools.ToDN(d.DNName)
}

// Domaines — voir ldapinterface.LDAPEntry.
//
// DNName porte tantôt « enov.local », tantôt « dc=enov,dc=local » selon le
// chemin qui a construit l'entrée. Le RBAC ne connaît que la première forme :
// la conversion est donc faite ici, et pas laissée à l'appelant.
func (d DomainEntry) Domaines() []string {
	nom := d.DNName
	if strings.Contains(nom, "=") {
		nom = ldaptools.ConvertLDAPBaseToDomainName(nom)
	}
	if nom == "" {
		return nil
	}
	return []string{nom}
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
	sub := "TRUE"
	if d.Feuille {
		sub = "FALSE"
	}
	all := map[string][]string{
		"objectclass":       d.ObjectClasses(),
		"dc":                {d.getDC()},
		"dn":                {d.DN()},
		AttrHasSubordinates: {sub},
	}
	// La règle commune : la version précédente servait tout attribut
	// opérationnel PORTANT UNE VALEUR, demandé ou non — y compris sur « 1.1 ».
	return selectionner(all, requested, typesOnly)
}

func (d DomainEntry) getDC() string {
	parts := strings.Split(d.DNName, ".")
	if len(parts) > 0 {
		return parts[0]
	}
	return d.DNName
}
