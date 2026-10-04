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
	ldapjournal "vaultaire/core/ldap/LDAP_Journal"
	"vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate"
	ldapinterface "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate/ldap_interface"
)

// resolveBaseScope gère les recherches LDAP scope=base (0).
// JumpServer/django-auth-ldap relit les attributs utilisateur (cn, uid, mail)
// via une recherche BASE sur le DN exact après authentification.
func resolveBaseScope(db *sql.DB, baseObject string, j *ldapjournal.Operation) []ldapinterface.LDAPEntry {
	baseObject = strings.TrimSpace(baseObject)
	baseLower := strings.ToLower(baseObject)

	if uid, ok := firstRDNValue(baseObject, "uid="); ok && dnHasOU(baseObject, "users") {
		if entry, ok := buildUserEntryForDN(db, uid, baseLower, j); ok {
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

func buildUserEntryForDN(db *sql.DB, username, expectedDN string, j *ldapjournal.Operation) (candidate.UserEntry, bool) {
	userObj, err := dbldap.GetUserByUsername(username, db)
	if err != nil {
		return candidate.UserEntry{}, false
	}

	domaineDuDN := ldaptools.ConvertLDAPBaseToDomainName(expectedDN)

	rattachements, lus := domainesDuCompte(db, username)
	if !lus {
		// LECTURE EN ÉCHEC : on refuse.
		//
		// Une panne de lecture ne doit pas se confondre avec « ce compte n'a aucun
		// domaine » : la version antérieure retombait dans ce cas sur le domaine
		// DEMANDÉ, celui que l'appelant venait de se voir autoriser. Le contrôle
		// d'accès se serait alors autorisé lui-même — le défaut du point 120,
		// reproduit sur un autre chemin et déclenchable par une erreur transitoire.
		j.Ecrire("ERROR", logs.CodeDBQuery, "domaines de "+username+
			" illisibles — entrée non rendue")
		return candidate.UserEntry{}, false
	}

	// UN COMPTE SANS AUCUN DOMAINE N'EST PAS RENDU — point 122.
	//
	// Un compte sans domaine est un compte sans groupe, donc sans aucun droit sur
	// le parc. Il ne peut déjà pas se lier (voir LDAP_bind.go) et il est déjà
	// introuvable par une recherche `one` ou `sub` — les comptes n'y sont
	// découverts qu'à travers leurs groupes. Le laisser lisible par son DN exact
	// était la seule brèche de cette règle ; elle est fermée.
	//
	// Le compte existe toujours, et se corrige depuis le portail ou `vlt` : c'est
	// là qu'on le rattache à un groupe. Ce qui disparaît est sa présence dans
	// l'annuaire, pas le compte.
	//
	// Le gestionnaire répondra `noSuchObject`, la même chose que pour un compte
	// inexistant. C'est voulu : pour LDAP, il n'existe pas.
	if len(rattachements) == 0 {
		j.Trace("%s n'appartient à aucun domaine — non rendu (point 122)", username)
		return candidate.UserEntry{}, false
	}

	baseDN := domaineDuDN
	{
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

	entry := candidate.UserEntry{
		User:          userObj,
		BaseDN:        baseDN,
		Rattachements: rattachements,
		Groups:        memberOfForUser(db, username, j),
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
		Name:        group.GroupName,
		BaseDN:      group.DomainName,
		Members:     memberDNs,
		Created_at:  group.Created_at,
		Modified_at: group.Modified_at,
		EntryUUID:   group.EntryUUID,
	}
	if strings.ToLower(entry.DN()) != expectedDN {
		return candidate.GroupEntry{}, false
	}
	return entry, true
}

// memberOfForUser rend les groupes d'un utilisateur : leur DN, et leur domaine.
//
// TOUS ses groupes, quel que soit leur domaine — et chacun avec le sien
// (TO-DO 132). Ce chemin est celui d'une recherche `base` sur le DN d'un
// compte : il rendait le `memberOf` complet à quiconque pouvait lire le compte,
// y compris les groupes de domaines qu'il n'a pas le droit de lire. Le tri est
// fait par le contrôle d'accès, sur le domaine porté ici.
//
// # Ce qui a changé
//
// La version antérieure lisait TOUS les groupes de l'annuaire, puis interrogeait
// chacun d'eux pour savoir s'il contenait l'utilisateur : 1 + N requêtes, soit
// 501 pour 500 groupes — et cela sur le chemin d'une recherche scope=base, celui
// qu'emprunte JumpServer après CHAQUE authentification.
//
// Une jointure répond à la même question en une requête.
func memberOfForUser(db *sql.DB, username string, j *ldapjournal.Operation) []candidate.Appartenance {
	groupes, err := dbldap.GetMemberOfByUsername(db, username)
	if err != nil {
		// Journalisé plutôt que silencieux : sans cela, une base en difficulté
		// rend un utilisateur sans aucun groupe, ce qu'un client lit comme une
		// perte d'appartenance — et non comme une panne.
		j.Ecrire("ERROR", logs.CodeDBQuery, "lecture des groupes de "+username+" : "+err.Error())
		return nil
	}

	var memberOf []candidate.Appartenance
	vus := make(map[string]struct{}, len(groupes))
	for _, g := range groupes {
		dn := fmt.Sprintf("cn=%s,ou=groups,%s", g.GroupName, ldaptools.ToRootDN(g.DomainName))
		if _, déjà := vus[dn]; déjà {
			continue
		}
		vus[dn] = struct{}{}
		memberOf = append(memberOf, candidate.Appartenance{DN: dn, Domaine: g.DomainName})
	}
	return memberOf
}
