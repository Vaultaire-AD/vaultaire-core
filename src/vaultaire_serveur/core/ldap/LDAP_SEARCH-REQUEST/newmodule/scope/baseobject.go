package scope

import (
	"strings"

	ldapinterface "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate/ldap_interface"
)

func ouFromBaseObject(baseObject string) (string, bool) {
	for _, part := range strings.Split(baseObject, ",") {
		part = strings.TrimSpace(part)
		if len(part) > 3 && strings.EqualFold(part[:3], "ou=") {
			return part[3:], true
		}
	}
	return "", false
}

func isUserContainerSearch(baseObject string) bool {
	ou, ok := ouFromBaseObject(baseObject)
	return ok && strings.EqualFold(ou, "users")
}

// FilterByBaseObject restreint les candidats au baseObject LDAP demandé (scope RFC 4511).
func FilterByBaseObject(entries []ldapinterface.LDAPEntry, baseObject string, scope int) []ldapinterface.LDAPEntry {
	baseObject = strings.TrimSpace(baseObject)
	if baseObject == "" || strings.EqualFold(baseObject, "cn=schema") {
		return entries
	}

	baseLower := strings.ToLower(baseObject)
	var result []ldapinterface.LDAPEntry

	for _, e := range entries {
		dn := strings.ToLower(e.DN())
		switch scope {
		case 0:
			if dn == baseLower {
				result = append(result, e)
			}
		case 1:
			if isDirectChildDN(dn, baseLower) {
				result = append(result, e)
			}
		default: // subtree
			if dn == baseLower || strings.HasSuffix(dn, ","+baseLower) {
				result = append(result, e)
			}
		}
	}
	return result
}

func isDirectChildDN(entryDN, baseDN string) bool {
	if !strings.HasSuffix(entryDN, ","+baseDN) {
		return false
	}
	remainder := strings.TrimSuffix(entryDN, ","+baseDN)
	return remainder != "" && !strings.Contains(remainder, ",")
}
