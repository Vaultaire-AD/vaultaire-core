package filter

import (
	"fmt"
	"strings"
	ldapinterface "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate/ldap_interface"
	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
	"vaultaire/core/logs"
)

// Evaluate applique un filtre LDAP à une entrée
func Evaluate(entry ldapinterface.LDAPEntry, f *ldapstorage.LDAPFilter, baseDN string, scope int) bool {
	if f == nil {
		return true
	}

	switch f.Type {

	case ldapstorage.FilterAnd:
		for _, c := range f.SubFilters {
			if !Evaluate(entry, c, baseDN, scope) {
				// fmt.Printf("[DEBUG] AND fail sur DN=%s pour sous-filtre %+v\n", entry.DN(), c)
				return false
			} else {
				// fmt.Printf("[DEBUG] AND success sur DN=%s pour sous-filtre %+v\n", entry.DN(), c)
			}
		}
		return true

	case ldapstorage.FilterOr:
		for _, c := range f.SubFilters {
			if Evaluate(entry, c, baseDN, scope) {
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
		res := !Evaluate(entry, f.SubFilters[0], baseDN, scope)
		// fmt.Printf("[DEBUG] NOT filter sur DN=%s => %v\n", entry.DN(), res)
		return res

	case ldapstorage.FilterSubstring:
		return evalSubstring(entry, f)

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

	case ldapstorage.FilterExtensible:
		// Extensible match - typically used for DN-aware assertions
		res := evalEquality(entry, f.Attribute, f.Value)
		// Log attribute and DN value for troubleshooting
		logs.Write_Log("DEBUG", fmt.Sprintf("Extensible match DN check for DN=%s attr=%s value=%s => %v", entry.DN(), f.Attribute, f.Value, res))
		return res

	default:
		// fmt.Printf("[WARN] Filtre LDAP inconnu Type=%v sur DN=%s\n", f.Type, entry.DN())
		return false
	}
}

func isInScope(entryDN, baseDN string, scope int) bool {
	entryDN = strings.ToLower(entryDN)
	baseDN = strings.ToLower(baseDN)

	// 1. Si c'est un match parfait (ou=users,dc=vaultaire,dc=local)
	if strings.HasSuffix(entryDN, baseDN) {
		return true
	}

	// 2. LOGIQUE SPÉCIFIQUE VAULTAIRE (Le "Saut" de sous-domaine)
	// On veut autoriser : ou=users,dc=admin,dc=vaultaire,dc=local
	// Pour une base :    ou=users,dc=vaultaire,dc=local

	if scope == 2 { // Subtree
		// On sépare la base demandée pour isoler "ou=users" et "dc=vaultaire,dc=local"
		parts := strings.SplitN(baseDN, ",", 2)
		if len(parts) < 2 {
			return strings.HasSuffix(entryDN, baseDN)
		}

		prefix := parts[0] // ex: "ou=users"
		suffix := parts[1] // ex: "dc=vaultaire,dc=local"

		// L'entrée est valide si elle commence par le préfixe (ou=users)
		// ET finit par le suffixe racine (dc=vaultaire,dc=local)
		return strings.HasPrefix(entryDN, prefix) && strings.HasSuffix(entryDN, suffix)
	}

	return false
}
