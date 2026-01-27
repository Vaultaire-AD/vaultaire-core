package response

import (
	ldapinterface "DUCKY/serveur/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate/ldap_interface"
	"DUCKY/serveur/ldap/LDAP_SEARCH-REQUEST/newmodule/ldap_types"
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

	return attrs
}

// // Build construit un SearchResultEntry à partir d'une entrée candidate
// func Build(entry ldapinterface.LDAPEntry, requested []string, typesOnly bool) ldap_types.SearchResultEntry {
// 	return ldap_types.SearchResultEntry{
// 		ObjectName: entry.DN(),
// 		Attributes: ResolveAttributes(entry, requested, typesOnly),
// 	}
// }

func BuildLDAPEntryForSend(entry ldapinterface.LDAPEntry, requestedAttrs []string) ldap_types.SearchResultEntry {
	// classes := entry.ObjectClasses()

	// déterminer si c'est un groupe ou un user
	// isGroup := false
	// for _, class := range classes {
	// 	if strings.ToLower(class) == "groupofnames" {
	// 		isGroup = true
	// 		break
	// 	}
	// }

	// fusionner les attributs demandés avec les obligatoires
	// var attributesToSend []string
	// if isGroup {
	// 	attributesToSend = ldaptools.MergeAttributes(requestedAttrs, ldaptools.MandatoryGroupAttrs)
	// } else {
	// 	attributesToSend = ldaptools.MergeAttributes(requestedAttrs, ldaptools.MandatoryUserAttrs)
	// }

	// construire les PartialAttribute
	var attrs []ldap_types.PartialAttribute
	for _, attr := range requestedAttrs {
		vals := entry.GetAttribute(attr)
		attrs = append(attrs, ldap_types.PartialAttribute{
			Type: attr,
			Vals: vals,
		})
	}

	return ldap_types.SearchResultEntry{
		ObjectName: entry.DN(),
		Attributes: attrs,
	}
}
