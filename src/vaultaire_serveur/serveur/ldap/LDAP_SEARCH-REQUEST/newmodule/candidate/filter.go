package candidate

import (
	"fmt"

	ldapinterface "DUCKY/serveur/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate/ldap_interface"
	"DUCKY/serveur/ldap/LDAP_SEARCH-REQUEST/newmodule/filter"
	ldapstorage "DUCKY/serveur/ldap/LDAP_Storage"
	"DUCKY/serveur/logs"
)

func DebugLDAPFilter(f *ldapstorage.LDAPFilter, indent string) {
	if f == nil {
		fmt.Println(indent + "<nil filter>")
		return
	}

	fmt.Println(indent + "LDAPFilter {")
	fmt.Println(indent+"  Type      :", f.Type)
	fmt.Println(indent+"  Attribute :", f.Attribute)
	fmt.Println(indent+"  Value     :", f.Value)

	if len(f.SubFilters) > 0 {
		fmt.Println(indent + "  SubFilters:")
		for i, sub := range f.SubFilters {
			fmt.Printf(indent+"    [%d]\n", i)
			DebugLDAPFilter(sub, indent+"      ")
		}
	} else {
		fmt.Println(indent + "  SubFilters: <none>")
	}

	fmt.Println(indent + "}")
}

// Filtre applique un filtre LDAP logique (LDAPFilter) à une liste d’entrées
func Filtre(entries []ldapinterface.LDAPEntry, f *ldapstorage.LDAPFilter) []ldapinterface.LDAPEntry {

	if f == nil {
		logs.Write_Log("DEBUG", "Filtre LDAP nil, toutes les entrées sont retournées")
		return entries
	}

	logs.Write_Log("DEBUG", fmt.Sprintf(
		"Application du filtre LDAP sur %d entrées (Type=%s)",
		len(entries),
		f.Type,
	))
	// DebugLDAPFilter(f, "  ")

	var result []ldapinterface.LDAPEntry

	for _, e := range entries {
		if filter.Evaluate(e, f) {
			result = append(result, e)
			logs.Write_Log("DEBUG", fmt.Sprintf(
				"Entrée %s correspond au filtre",
				e.DN(),
			))
		} else {
			logs.Write_Log("DEBUG", fmt.Sprintf(
				"Entrée %s ne correspond PAS au filtre",
				e.DN(),
			))
		}
	}

	logs.Write_Log("DEBUG", fmt.Sprintf(
		"Filtre LDAP appliqué : %d/%d entrées correspondent",
		len(result),
		len(entries),
	))

	return result
}
