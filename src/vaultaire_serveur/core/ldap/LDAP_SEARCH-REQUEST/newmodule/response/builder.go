package response

import (
	"fmt"
	ldapinterface "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate/ldap_interface"
	"vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/ldap_types"
	"vaultaire/core/logs"
)

// ResolveAttributes récupère les attributs demandés pour une entrée
func ResolveAttributes(entry ldapinterface.LDAPEntry, requested []string, typesOnly bool) []ldap_types.PartialAttribute {
	attrs := []ldap_types.PartialAttribute{}

	if typesOnly {
		// TypesOnly = true → renvoyer un minimum
		attrs = append(attrs, ldap_types.PartialAttribute{
			Type: "dn",
			Vals: []string{entry.DN()},
		})
		attrs = append(attrs, ldap_types.PartialAttribute{
			Type: "objectClass",
			Vals: entry.ObjectClasses(),
		})
		return attrs
	}

	for _, attr := range requested {
		vals := entry.GetAttribute(attr)
		if vals != nil && len(vals) > 0 {
			attrs = append(attrs, ldap_types.PartialAttribute{
				Type: attr,
				Vals: vals,
			})
		}
	}

	// Toujours renvoyer l'objectClass et DN
	attrs = append(attrs, ldap_types.PartialAttribute{
		Type: "dn",
		Vals: []string{entry.DN()},
	})
	attrs = append(attrs, ldap_types.PartialAttribute{
		Type: "objectClass",
		Vals: entry.ObjectClasses(),
	})

	logs.Write_Log("DEBUG", "Attributs résolus pour l'entrée "+entry.DN()+":")
	for _, a := range attrs {
		logs.Write_Log("DEBUG", "  "+a.Type+": "+fmt.Sprintf("%v", a.Vals))
	}
	return attrs
}

// // Build construit un SearchResultEntry à partir d'une entrée candidate
// func Build(entry ldapinterface.LDAPEntry, requested []string, typesOnly bool) ldap_types.SearchResultEntry {
// 	return ldap_types.SearchResultEntry{
// 		ObjectName: entry.DN(),
// 		Attributes: ResolveAttributes(entry, requested, typesOnly),
// 	}
// }

func BuildLDAPEntryForSend(entry ldapinterface.LDAPEntry, requestedAttrs []string, typesOnly bool) ldap_types.SearchResultEntry {
	if len(requestedAttrs) == 0 {
		requestedAttrs = []string{"*"}
	}
	attrMap := entry.GetAttributes(requestedAttrs, typesOnly)
	attrs := make([]ldap_types.PartialAttribute, 0, len(attrMap))
	for typ, vals := range attrMap {
		attrs = append(attrs, ldap_types.PartialAttribute{
			Type: typ,
			Vals: vals,
		})
	}

	return ldap_types.SearchResultEntry{
		ObjectName: entry.DN(),
		Attributes: attrs,
	}
}
