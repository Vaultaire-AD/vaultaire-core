package scope

import (
	"database/sql"
	"fmt"
	"strings"

	"vaultaire/core/database"
	ldaptools "vaultaire/core/ldap/LDAP-TOOLS"
	"vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate"
	ldapinterface "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate/ldap_interface"
)

// resolveBaseScope gère les recherches LDAP scope=base (0).
// JumpServer/django-auth-ldap relit les attributs utilisateur (cn, uid, mail)
// via une recherche BASE sur le DN exact après authentification.
func resolveBaseScope(db *sql.DB, baseObject string) []ldapinterface.LDAPEntry {
	baseObject = strings.TrimSpace(baseObject)
	baseLower := strings.ToLower(baseObject)

	if uid, ok := firstRDNValue(baseObject, "uid="); ok && dnHasOU(baseObject, "users") {
		if entry, ok := buildUserEntryForDN(db, uid, baseLower); ok {
			return []ldapinterface.LDAPEntry{entry}
		}
		return nil
	}

	if groupName, ok := firstRDNValue(baseObject, "cn="); ok && dnHasOU(baseObject, "groups") {
		if entry, ok := buildGroupEntryForDN(db, groupName, baseLower); ok {
			return []ldapinterface.LDAPEntry{entry}
		}
		return nil
	}

	if ouName, ok := ouFromBaseObject(baseObject); ok {
		domain := ldaptools.ConvertLDAPBaseToDomainName(baseObject)
		entry := candidate.OUEntry{Name: ouName, BaseDN: domain}
		if strings.ToLower(entry.DN()) == baseLower {
			return []ldapinterface.LDAPEntry{entry}
		}
		return nil
	}

	domain := ldaptools.ConvertLDAPBaseToDomainName(baseObject)
	if domain != "" && isDomainOnlyDN(baseObject) {
		entry := candidate.DomainEntry{DNName: domain}
		if strings.ToLower(entry.DN()) == baseLower {
			return []ldapinterface.LDAPEntry{entry}
		}
	}
	return nil
}

func firstRDNValue(dn, prefix string) (string, bool) {
	parts := strings.SplitN(dn, ",", 2)
	if len(parts) == 0 {
		return "", false
	}
	first := strings.TrimSpace(parts[0])
	if !strings.HasPrefix(strings.ToLower(first), strings.ToLower(prefix)) {
		return "", false
	}
	return strings.TrimSpace(first[len(prefix):]), true
}

func dnHasOU(dn, ouName string) bool {
	for _, part := range strings.Split(dn, ",") {
		part = strings.TrimSpace(part)
		if strings.EqualFold(part, "ou="+ouName) {
			return true
		}
	}
	return false
}

func isDomainOnlyDN(dn string) bool {
	for _, part := range strings.Split(dn, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.HasPrefix(strings.ToLower(part), "dc=") {
			return false
		}
	}
	return true
}

func buildUserEntryForDN(db *sql.DB, username, expectedDN string) (candidate.UserEntry, bool) {
	userObj, err := database.GetUserByUsername(username, db)
	if err != nil {
		return candidate.UserEntry{}, false
	}

	baseDN := ldaptools.ConvertLDAPBaseToDomainName(expectedDN)
	if userID, err := database.Get_User_ID_By_Username(db, username); err == nil {
		if domains, err := database.GetDomainsForUser(db, userID); err == nil && len(domains) > 0 {
			baseDN = domains[0]
		}
	}

	entry := candidate.UserEntry{
		User:        userObj,
		BaseDN:      baseDN,
		Groups:      userMemberOf(db, username),
		DisplayName: userObj.Firstname + " " + userObj.Lastname,
		GivenName:   userObj.Firstname,
		Sn:          userObj.Lastname,
		Uid:         userObj.Username,
	}
	if strings.ToLower(entry.DN()) != expectedDN {
		return candidate.UserEntry{}, false
	}
	return entry, true
}

func buildGroupEntryForDN(db *sql.DB, groupName, expectedDN string) (candidate.GroupEntry, bool) {
	group, err := database.GetGroupWithUsersByName(db, groupName)
	if err != nil {
		return candidate.GroupEntry{}, false
	}

	domainDN := ldaptools.ToRootDN(group.DomainName)
	memberDNs := make([]string, len(group.Users))
	for i, u := range group.Users {
		memberDNs[i] = fmt.Sprintf("uid=%s,ou=users,%s", u, domainDN)
	}

	entry := candidate.GroupEntry{
		Name:    group.GroupName,
		BaseDN:  group.DomainName,
		Members: memberDNs,
	}
	if strings.ToLower(entry.DN()) != expectedDN {
		return candidate.GroupEntry{}, false
	}
	return entry, true
}

func userMemberOf(db *sql.DB, username string) []string {
	groups, err := database.GetAllGroupsWithDomains(db)
	if err != nil {
		return nil
	}
	var memberOf []string
	for _, g := range groups {
		groupData, err := database.GetGroupWithUsersByName(db, g.GroupName)
		if err != nil {
			continue
		}
		for _, u := range groupData.Users {
			if strings.EqualFold(u, username) {
				memberOf = append(memberOf, fmt.Sprintf("cn=%s,ou=groups,%s", groupData.GroupName, ldaptools.ToRootDN(groupData.DomainName)))
				break
			}
		}
	}
	return memberOf
}
