package scope

import (
	"strings"

	ldaptools "vaultaire/core/ldap/LDAP-TOOLS"
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
		if entryMatchesBaseObject(strings.ToLower(e.DN()), baseLower, scope) {
			result = append(result, e)
		}
	}
	return result
}

func entryMatchesBaseObject(entryDN, baseDN string, scope int) bool {
	switch scope {
	case 0:
		return entryDN == baseDN
	case 1:
		if isDirectChildDN(entryDN, baseDN) {
			return true
		}
		return entryInVaultaireOneLevel(entryDN, baseDN)
	default: // subtree
		if entryDN == baseDN || strings.HasSuffix(entryDN, ","+baseDN) {
			return true
		}
		return entryInVaultaireSubtree(entryDN, baseDN)
	}
}

// Vaultaire stocke les entrées sous ToRootDN(domain) (ex. dc=enov,dc=local)
// alors que les clients cherchent souvent le DN complet du sous-domaine
// (ex. dc=bastion,dc=admin,dc=enov,dc=local).
func entryInVaultaireSubtree(entryDN, baseDN string) bool {
	domain := ldaptools.ConvertLDAPBaseToDomainName(baseDN)
	if domain == "" {
		return false
	}
	rootDN := strings.ToLower(ldaptools.ToRootDN(domain))
	if entryDN == rootDN || strings.HasSuffix(entryDN, ","+rootDN) {
		return true
	}

	prefix, suffix, ok := strings.Cut(baseDN, ",")
	if !ok {
		return false
	}
	rootFromSuffix := strings.ToLower(ldaptools.ToRootDN(ldaptools.ConvertLDAPBaseToDomainName(suffix)))
	return strings.HasPrefix(entryDN, prefix) &&
		(strings.HasSuffix(entryDN, ","+suffix) || strings.HasSuffix(entryDN, ","+rootFromSuffix))
}

func entryInVaultaireOneLevel(entryDN, baseDN string) bool {
	ouName, ok := ouFromBaseObject(baseDN)
	if !ok {
		return false
	}
	domain := ldaptools.ConvertLDAPBaseToDomainName(baseDN)
	if domain == "" {
		return false
	}
	containerDN := strings.ToLower("ou=" + ouName + "," + ldaptools.ToRootDN(domain))
	if entryDN == containerDN {
		return false
	}
	if !strings.HasSuffix(entryDN, ","+containerDN) {
		return false
	}
	remainder := strings.TrimSuffix(entryDN, ","+containerDN)
	return remainder != "" && !strings.Contains(remainder, ",")
}

func isDirectChildDN(entryDN, baseDN string) bool {
	if !strings.HasSuffix(entryDN, ","+baseDN) {
		return false
	}
	remainder := strings.TrimSuffix(entryDN, ","+baseDN)
	return remainder != "" && !strings.Contains(remainder, ",")
}
