package scope

import (
	"database/sql"
	"fmt"
	"strings"
	dbdomains "vaultaire/core/database/db_domains"
	dbldap "vaultaire/core/database/db_ldap"
	dbusers "vaultaire/core/database/db_users"
	"vaultaire/core/logs"

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
	userObj, err := dbldap.GetUserByUsername(username, db)
	if err != nil {
		return candidate.UserEntry{}, false
	}

	baseDN := ldaptools.ConvertLDAPBaseToDomainName(expectedDN)
	if userID, err := dbusers.Get_User_ID_By_Username(db, username); err == nil {
		if domains, err := dbdomains.GetDomainsForUser(db, userID); err == nil && len(domains) > 0 {
			baseDN = domains[0]
		}
	}

	entry := candidate.UserEntry{
		User:        userObj,
		BaseDN:      baseDN,
		Groups:      memberOfForUser(db, username),
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
	group, err := dbldap.GetGroupWithUsersByName(db, groupName)
	if err != nil || group == nil {
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

// memberOfForUser rend les DN des groupes d'un utilisateur.
//
// # Ce qui a changé
//
// La version antérieure lisait TOUS les groupes de l'annuaire, puis interrogeait
// chacun d'eux pour savoir s'il contenait l'utilisateur : 1 + N requêtes, soit
// 501 pour 500 groupes — et cela sur le chemin d'une recherche scope=base, celui
// qu'emprunte JumpServer après CHAQUE authentification.
//
// Une jointure répond à la même question en une requête.
func memberOfForUser(db *sql.DB, username string) []string {
	groupes, err := dbldap.GetMemberOfByUsername(db, username)
	if err != nil {
		// Journalisé plutôt que silencieux : sans cela, une base en difficulté
		// rend un utilisateur sans aucun groupe, ce qu'un client lit comme une
		// perte d'appartenance — et non comme une panne.
		logs.Write_Log("ERROR", "ldap: lecture des groupes de "+username+" : "+err.Error())
		return nil
	}

	var memberOf []string
	vus := make(map[string]struct{}, len(groupes))
	for _, g := range groupes {
		dn := fmt.Sprintf("cn=%s,ou=groups,%s", g.GroupName, ldaptools.ToRootDN(g.DomainName))
		if _, déjà := vus[dn]; déjà {
			continue
		}
		vus[dn] = struct{}{}
		memberOf = append(memberOf, dn)
	}
	return memberOf
}
