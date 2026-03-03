package filter

import (
	ldapinterface "vaultaire/serveur/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate/ldap_interface"
	ldapstorage "vaultaire/serveur/ldap/LDAP_Storage"
)

// Evaluate applique un filtre LDAP à une entrée
func Evaluate(entry ldapinterface.LDAPEntry, f *ldapstorage.LDAPFilter) bool {
	if f == nil {
		return true
	}

	switch f.Type {

	case ldapstorage.FilterAnd:
		for _, c := range f.SubFilters {
			if !Evaluate(entry, c) {
				// fmt.Printf("[DEBUG] AND fail sur DN=%s pour sous-filtre %+v\n", entry.DN(), c)
				return false
			} else {
				// fmt.Printf("[DEBUG] AND success sur DN=%s pour sous-filtre %+v\n", entry.DN(), c)
			}
		}
		return true

	case ldapstorage.FilterOr:
		for _, c := range f.SubFilters {
			if Evaluate(entry, c) {
				// fmt.Printf("[DEBUG] OR success sur DN=%s pour sous-filtre %+v\n", entry.DN(), c)
				return true
			} else {
				// fmt.Printf("[DEBUG] OR fail sur DN=%s pour sous-filtre %+v\n", entry.DN(), c)
			}
		}
		return false

	case ldapstorage.FilterNot:
		if len(f.SubFilters) != 1 {
			// fmt.Printf("[WARN] NOT filter avec != 1 subfilter sur DN=%s\n", entry.DN())
			return false
		}
		res := !Evaluate(entry, f.SubFilters[0])
		// fmt.Printf("[DEBUG] NOT filter sur DN=%s => %v\n", entry.DN(), res)
		return res

	case ldapstorage.FilterEquality:
		res := evalEquality(entry, f.Attribute, f.Value)
		// fmt.Printf("[DEBUG] Equality filter DN=%s attr=%s val=%s => %v (entry values=%v)\n",
		// 	entry.DN(), f.Attribute, f.Value, res, entry.GetAttribute(f.Attribute))
		return res

	case ldapstorage.FilterPresent:
		res := evalPresent(entry, f.Attribute)
		// fmt.Printf("[DEBUG] Present filter DN=%s attr=%s => %v (entry values=%v)\n",
		// 	entry.DN(), f.Attribute, res, entry.GetAttribute(f.Attribute))
		return res

	default:
		// fmt.Printf("[WARN] Filtre LDAP inconnu Type=%v sur DN=%s\n", f.Type, entry.DN())
		return false
	}
}
