package scope

import (
	"database/sql"
	"fmt"
	"sort"
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

	domaineDuDN := ldaptools.ConvertLDAPBaseToDomainName(expectedDN)

	rattachements, lus := domainesDuCompte(db, username)
	if !lus {
		// LECTURE EN ÉCHEC : on REFUSE, on ne retombe pas sur le domaine demandé.
		//
		// Le secours ci-dessous est réservé au compte qui n'a réellement aucun
		// domaine. L'appliquer aussi à une panne de lecture rattacherait le compte
		// au domaine que l'appelant vient de se voir autoriser — donc le filtre
		// s'autoriserait lui-même, ce qui est exactement le défaut du point 120,
		// reproduit sur un autre chemin et déclenchable par une erreur transitoire.
		//
		// Partout ailleurs dans ce correctif, une lecture de droits qui échoue
		// refuse ; ici aussi.
		logs.Write_Log("ERROR", "ldap: domaines de "+username+
			" illisibles — entrée non rendue")
		return candidate.UserEntry{}, false
	}

	baseDN := domaineDuDN
	if len(rattachements) > 0 {
		// Le domaine qui compose le DN : celui des rattachements qui redonne le DN
		// demandé, et à défaut le premier dans l'ordre alphabétique.
		//
		// La version antérieure prenait `domains[0]` sans plus de façon, alors que
		// `GetDomainsForUser` n'a AUCUN ORDER BY. Dans un même arbre cela ne se
		// voyait pas — `ToRootDN` ne garde que les deux derniers labels, donc
		// `admin.enov.local` et `enov.local` composent le même DN. Mais pour un
		// compte membre de groupes dans DEUX arbres (`enov.local` et `acme.fr`), le
		// DN construit tombait tantôt sur l'un tantôt sur l'autre : la comparaison
		// finale échouait une fois sur deux et le compte devenait introuvable par
		// intermittence — sur le chemin que JumpServer emprunte après CHAQUE
		// authentification.
		baseDN = rattachements[0]
		for _, d := range rattachements {
			if strings.EqualFold(ldaptools.ToRootDN(d), ldaptools.ToRootDN(domaineDuDN)) {
				baseDN = d
				break
			}
		}
	}

	// Compte sans aucun domaine : on retient celui du DN demandé.
	//
	// Il n'appartient à aucun groupe, donc à aucune délégation : le refuser ne
	// protégerait personne, et le rendrait illisible alors qu'il l'est
	// aujourd'hui. Le domaine du DN est par ailleurs celui que l'appelant vient de
	// se voir autoriser à l'entrée, donc ce secours n'ouvre rien.
	//
	// Ce cas est celui du point 122 — un compte sans groupe est déjà introuvable
	// par une recherche `one` ou `sub`, et n'est lisible que par son DN exact.
	// C'est là qu'il faudra décider ce qu'un tel compte est censé être.
	if len(rattachements) == 0 && domaineDuDN != "" {
		rattachements = []string{domaineDuDN}
	}

	entry := candidate.UserEntry{
		User:          userObj,
		BaseDN:        baseDN,
		Rattachements: rattachements,
		Groups:        memberOfForUser(db, username),
		DisplayName:   userObj.Firstname + " " + userObj.Lastname,
		GivenName:     userObj.Firstname,
		Sn:            userObj.Lastname,
		Uid:           userObj.Username,
	}
	if strings.ToLower(entry.DN()) != expectedDN {
		return candidate.UserEntry{}, false
	}
	return entry, true
}

// domainesDuCompte rend les domaines d'un compte, triés, et dit si la LECTURE a
// abouti.
//
// Le second retour distingue « ce compte n'a aucun domaine » de « je n'ai pas pu
// savoir ». Les deux se ressemblaient — une liste vide dans les deux cas — et
// c'est ce qui permettait à une panne de base de passer pour un compte sans
// groupe, donc de déclencher un secours qui ouvre.
func domainesDuCompte(db *sql.DB, username string) (domaines []string, lus bool) {
	userID, err := dbusers.Get_User_ID_By_Username(db, username)
	if err != nil {
		return nil, false
	}
	domains, err := dbdomains.GetDomainsForUser(db, userID)
	if err != nil {
		return nil, false
	}
	domaines = append(domaines, domains...)
	// Trié : `GetDomainsForUser` n'a aucun ORDER BY, et une liste dont l'ordre
	// change d'une exécution à l'autre rend les journaux incomparables.
	sort.Strings(domaines)
	return domaines, true
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
